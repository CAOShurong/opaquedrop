package server

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/CAOShurong/opaquedrop/internal/model"
	"github.com/CAOShurong/opaquedrop/internal/store"
)

//go:embed web/*
var webFiles embed.FS

type Server struct {
	Store     *store.Store
	Logger    *log.Logger
	Limiter   *failureLimiter
	clientIPs clientIPResolver
}

type Option func(*Server)

func WithTrustedProxies(prefixes []netip.Prefix) Option {
	trusted := append([]netip.Prefix(nil), prefixes...)
	return func(s *Server) {
		s.clientIPs = newClientIPResolver(trusted)
	}
}

func New(s *store.Store, logger *log.Logger, options ...Option) *Server {
	if logger == nil {
		logger = log.Default()
	}
	result := &Server{Store: s, Logger: logger, Limiter: newFailureLimiter(), clientIPs: newClientIPResolver(nil)}
	for _, option := range options {
		option(result)
	}
	return result
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.landing)
	mux.HandleFunc("GET /r/{id}", s.requestPage)
	mux.HandleFunc("GET /assets/{name}", s.asset)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /api/v1/requests/{id}", s.requestInfo)
	mux.HandleFunc("POST /api/v1/requests/{id}/uploads", s.beginUpload)
	mux.HandleFunc("PUT /api/v1/requests/{id}/uploads/{upload}/chunks/{index}", s.putChunk)
	mux.HandleFunc("HEAD /api/v1/requests/{id}/uploads/{upload}/chunks/{index}", s.headChunk)
	mux.HandleFunc("POST /api/v1/requests/{id}/uploads/{upload}/complete", s.completeUpload)
	mux.HandleFunc("GET /api/v1/collect/{id}/uploads", s.listUploads)
	mux.HandleFunc("POST /api/v1/collect/{id}/close", s.closeRequest)
	mux.HandleFunc("GET /api/v1/collect/{id}/uploads/{upload}/manifest", s.collectManifest)
	mux.HandleFunc("GET /api/v1/collect/{id}/uploads/{upload}/chunks/{index}", s.collectChunk)
	mux.HandleFunc("POST /api/v1/collect/{id}/uploads/{upload}/ack", s.acknowledge)
	return s.securityHeaders(s.originBoundary(mux))
}

func (s *Server) Listen(address string) error {
	httpServer := &http.Server{
		Addr: address, Handler: s.Handler(),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 32 << 10,
	}
	s.Logger.Printf("OpaqueDrop listening on http://%s", address)
	return httpServer.ListenAndServe()
}

func (s *Server) landing(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.serveWeb(w, "web/index.html", "text/html; charset=utf-8")
}

func (s *Server) requestPage(w http.ResponseWriter, r *http.Request) {
	closed, err := s.Store.Closed(r.PathValue("id"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, err)
		return
	}
	if closed {
		s.storeError(w, store.ErrClosed)
		return
	}
	if _, err := s.Store.Request(r.PathValue("id")); err != nil {
		http.NotFound(w, r)
		return
	}
	s.serveWeb(w, "web/request.html", "text/html; charset=utf-8")
}

func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.PathValue("name"))
	if name != r.PathValue("name") || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	contentType := mime.TypeByExtension(filepath.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	s.serveWeb(w, "web/"+name, contentType)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "opaquedrop", "protocol": model.ProtocolVersion})
}

func (s *Server) requestInfo(w http.ResponseWriter, r *http.Request) {
	bundle, ok := s.submitAuth(w, r)
	if !ok {
		return
	}
	if !bundle.ExpiresAt.After(time.Now()) {
		writeError(w, http.StatusGone, "REQUEST_EXPIRED", "This request has expired.")
		return
	}
	info, err := s.Store.Info(bundle)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) beginUpload(w http.ResponseWriter, r *http.Request) {
	bundle, ok := s.submitAuth(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, store.MaxManifest)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "MANIFEST_TOO_LARGE", "The upload manifest is too large.")
		return
	}
	manifest, err := s.Store.BeginUpload(bundle, raw)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"upload_id": manifest.UploadID, "chunk_count": manifest.ChunkCount})
}

func (s *Server) putChunk(w http.ResponseWriter, r *http.Request) {
	_, ok := s.submitAuth(w, r)
	if !ok {
		return
	}
	index, err := store.ParseChunkIndex(r.PathValue("index"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_CHUNK", "The chunk index is invalid.")
		return
	}
	err = s.Store.PutChunk(r.PathValue("id"), r.PathValue("upload"), index, r.Body, r.ContentLength)
	if err != nil {
		s.storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) headChunk(w http.ResponseWriter, r *http.Request) {
	_, ok := s.submitAuth(w, r)
	if !ok {
		return
	}
	index, err := store.ParseChunkIndex(r.PathValue("index"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_CHUNK", "The chunk index is invalid.")
		return
	}
	digest, err := s.Store.ChunkDigest(r.PathValue("id"), r.PathValue("upload"), index)
	if err != nil {
		s.storeError(w, err)
		return
	}
	w.Header().Set("X-OpaqueDrop-SHA256", digest)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) completeUpload(w http.ResponseWriter, r *http.Request) {
	_, ok := s.submitAuth(w, r)
	if !ok {
		return
	}
	receipt, err := s.Store.Complete(r.PathValue("id"), r.PathValue("upload"))
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func (s *Server) listUploads(w http.ResponseWriter, r *http.Request) {
	_, ok := s.collectAuth(w, r)
	if !ok {
		return
	}
	receipts, err := s.Store.ListReceipts(r.PathValue("id"))
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"uploads": receipts})
}

func (s *Server) closeRequest(w http.ResponseWriter, r *http.Request) {
	_, ok := s.collectAuth(w, r)
	if !ok {
		return
	}
	closure, err := s.Store.CloseRequest(r.PathValue("id"))
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, closure)
}

func (s *Server) collectManifest(w http.ResponseWriter, r *http.Request) {
	_, ok := s.collectAuth(w, r)
	if !ok {
		return
	}
	b, err := s.Store.ReadManifest(r.PathValue("id"), r.PathValue("upload"))
	if err != nil {
		s.storeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (s *Server) collectChunk(w http.ResponseWriter, r *http.Request) {
	_, ok := s.collectAuth(w, r)
	if !ok {
		return
	}
	index, err := store.ParseChunkIndex(r.PathValue("index"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_CHUNK", "The chunk index is invalid.")
		return
	}
	f, size, err := s.Store.OpenChunk(r.PathValue("id"), r.PathValue("upload"), index)
	if err != nil {
		s.storeError(w, err)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(size))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

func (s *Server) acknowledge(w http.ResponseWriter, r *http.Request) {
	bundle, ok := s.collectAuth(w, r)
	if !ok {
		return
	}
	if err := s.Store.Acknowledge(bundle, r.PathValue("upload")); err != nil {
		s.storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) submitAuth(w http.ResponseWriter, r *http.Request) (model.RequestBundle, bool) {
	return s.authorize(w, r, "submit")
}

func (s *Server) collectAuth(w http.ResponseWriter, r *http.Request) (model.RequestBundle, bool) {
	return s.authorize(w, r, "collect")
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, kind string) (model.RequestBundle, bool) {
	ip := s.clientIPs.resolve(r)
	if s.Limiter.blocked(ip) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "AUTH_RATE_LIMITED", "Too many failed authorization attempts. Try again later.")
		return model.RequestBundle{}, false
	}
	header := r.Header.Get("Authorization")
	token := ""
	if strings.HasPrefix(header, "OpaqueDrop ") {
		token = strings.TrimPrefix(header, "OpaqueDrop ")
	}
	bundle, ok := s.Store.Authenticate(r.PathValue("id"), token, kind)
	if !ok {
		s.Limiter.failure(ip)
		writeError(w, http.StatusUnauthorized, "INVALID_CAPABILITY", "The capability is missing or invalid.")
		return model.RequestBundle{}, false
	}
	if kind == "submit" {
		closed, err := s.Store.Closed(bundle.ID)
		if err != nil {
			s.storeError(w, err)
			return model.RequestBundle{}, false
		}
		if closed {
			s.storeError(w, store.ErrClosed)
			return model.RequestBundle{}, false
		}
	}
	return bundle, true
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
				writeError(w, http.StatusForbidden, "CROSS_ORIGIN_DENIED", "Cross-origin API requests are not allowed.")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				parsed, err := url.Parse(origin)
				if err != nil || !strings.EqualFold(parsed.Host, r.Host) {
					writeError(w, http.StatusForbidden, "CROSS_ORIGIN_DENIED", "Cross-origin API requests are not allowed.")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) serveWeb(w http.ResponseWriter, path, contentType string) {
	b, err := webFiles.ReadFile(path)
	if err != nil {
		s.internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (s *Server) storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "NOT_FOUND", "The requested upload was not found.")
	case errors.Is(err, store.ErrExpired):
		writeError(w, http.StatusGone, "REQUEST_EXPIRED", "This request has expired.")
	case errors.Is(err, store.ErrClosed):
		writeError(w, http.StatusGone, "REQUEST_CLOSED", "This request is closed to new submissions.")
	case errors.Is(err, store.ErrQuota):
		writeError(w, http.StatusRequestEntityTooLarge, "REQUEST_QUOTA_EXCEEDED", "This upload exceeds the request quota.")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "UPLOAD_CONFLICT", "The upload state conflicts with this request.")
	case errors.Is(err, store.ErrInvalid):
		writeError(w, http.StatusBadRequest, "INVALID_UPLOAD", err.Error())
	default:
		s.internalError(w, err)
	}
}

func (s *Server) internalError(w http.ResponseWriter, err error) {
	s.Logger.Printf("internal error: %v", err)
	writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "The server could not complete the request.")
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
