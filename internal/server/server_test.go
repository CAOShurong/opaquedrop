package server_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CAOShurong/opaquedrop/internal/collector"
	"github.com/CAOShurong/opaquedrop/internal/core"
	"github.com/CAOShurong/opaquedrop/internal/cryptobox"
	"github.com/CAOShurong/opaquedrop/internal/model"
	"github.com/CAOShurong/opaquedrop/internal/server"
	"github.com/CAOShurong/opaquedrop/internal/store"
)

type fixture struct {
	root        string
	bundle      model.RequestBundle
	key         model.KeyFile
	submitToken string
	server      *httptest.Server
	logs        *bytes.Buffer
}

type sealedUpload struct {
	manifest model.Manifest
	raw      []byte
	chunks   [][]byte
}

func newFixture(t *testing.T, maxFiles int, maxBytes int64) *fixture {
	return newFixtureWithOptions(t, maxFiles, maxBytes)
}

func newFixtureWithOptions(t *testing.T, maxFiles int, maxBytes int64, options ...server.Option) *fixture {
	t.Helper()
	root := t.TempDir()
	s := store.New(root)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	httpServer := httptest.NewServer(server.New(s, log.New(logs, "", 0), options...).Handler())
	t.Cleanup(httpServer.Close)
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	bundle, key, err := core.MakeRequest(httpServer.URL, "DEMO — confidential intake", now, now.Add(24*time.Hour), maxFiles, maxBytes, false)
	if err != nil {
		t.Fatal(err)
	}
	// The test clock is historical relative to runtime, so use a future expiry.
	bundle.ExpiresAt = time.Now().Add(24 * time.Hour).UTC()
	key.ExpiresAt = bundle.ExpiresAt
	if err := s.ImportRequest(bundle); err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(key.SubmitURL)
	values, _ := url.ParseQuery(parsed.Fragment)
	return &fixture{root: root, bundle: bundle, key: key, submitToken: values.Get("t"), server: httpServer, logs: logs}
}

func TestTrustedProxySeparatesAuthorizationFailureBuckets(t *testing.T) {
	t.Run("explicit trust isolates forwarded clients", func(t *testing.T) {
		f := newFixtureWithOptions(t, 1, 1<<20, server.WithTrustedProxies([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}))
		path := "/api/v1/requests/" + f.bundle.ID
		for i := 0; i < 12; i++ {
			response, _ := request(t, f, http.MethodGet, path, "invalid", nil, map[string]string{"X-Forwarded-For": "198.51.100.10"})
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("failure %d status = %d", i+1, response.StatusCode)
			}
		}
		response, _ := request(t, f, http.MethodGet, path, "invalid", nil, map[string]string{"X-Forwarded-For": "198.51.100.10"})
		if response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") != "60" {
			t.Fatalf("limited client status = %d, Retry-After = %q", response.StatusCode, response.Header.Get("Retry-After"))
		}
		response, _ = request(t, f, http.MethodGet, path, f.submitToken, nil, map[string]string{"X-Forwarded-For": "198.51.100.11"})
		if response.StatusCode != http.StatusOK {
			t.Fatalf("independent submit client status = %d", response.StatusCode)
		}
		response, _ = request(t, f, http.MethodGet, "/api/v1/collect/"+f.bundle.ID+"/uploads", f.key.CollectToken, nil, map[string]string{"X-Forwarded-For": "198.51.100.12"})
		if response.StatusCode != http.StatusOK {
			t.Fatalf("independent collect client status = %d", response.StatusCode)
		}
	})

	t.Run("default ignores spoofed forwarding addresses", func(t *testing.T) {
		f := newFixture(t, 1, 1<<20)
		path := "/api/v1/requests/" + f.bundle.ID
		for i := 0; i < 12; i++ {
			response, _ := request(t, f, http.MethodGet, path, "invalid", nil, map[string]string{"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", i+1)})
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("failure %d status = %d", i+1, response.StatusCode)
			}
		}
		response, _ := request(t, f, http.MethodGet, path, f.submitToken, nil, map[string]string{"X-Forwarded-For": "203.0.113.9"})
		if response.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("spoofed forwarding header bypassed peer limiter: status = %d", response.StatusCode)
		}
	})
}

func seal(t *testing.T, f *fixture, uploadID string, plaintext []byte, name string, chunkSize int64) sealedUpload {
	t.Helper()
	if uploadID == "" {
		var err error
		uploadID, err = core.RandomToken(16)
		if err != nil {
			t.Fatal(err)
		}
	}
	recipientBytes, _ := base64.RawURLEncoding.DecodeString(f.bundle.PublicKey)
	recipient, err := ecdh.P256().NewPublicKey(recipientBytes)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, 32)
	prefix := make([]byte, 8)
	_, _ = rand.Read(salt)
	_, _ = rand.Read(prefix)
	chunkCount := int((int64(len(plaintext)) + chunkSize - 1) / chunkSize)
	if chunkCount == 0 {
		chunkCount = 1
	}
	manifest := model.Manifest{
		Version: model.ProtocolVersion, RequestID: f.bundle.ID, UploadID: uploadID, Algorithm: model.Algorithm,
		EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		Salt:               base64.RawURLEncoding.EncodeToString(salt), NoncePrefix: base64.RawURLEncoding.EncodeToString(prefix),
		ChunkSize: chunkSize, ChunkCount: chunkCount, PlainSize: int64(len(plaintext)),
	}
	manifest.HeaderSHA256 = cryptobox.HeaderSHA256(manifest)
	keyBytes, err := hkdf.Key(sha256.New, shared, salt, cryptobox.KDFInfo(f.bundle.ID, uploadID), 32)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(keyBytes)
	gcm, _ := cipher.NewGCM(block)
	metadata, _ := json.Marshal(model.FileMetadata{Name: name, Type: "application/octet-stream", LastModified: 1700000000000})
	manifest.EncryptedMetadata = base64.RawURLEncoding.EncodeToString(gcm.Seal(nil, testNonce(prefix, ^uint32(0)), metadata, []byte(cryptobox.MetadataAAD(f.bundle.ID, uploadID, manifest.HeaderSHA256))))
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	chunks := make([][]byte, chunkCount)
	for i := 0; i < chunkCount; i++ {
		start := int64(i) * chunkSize
		end := min(int64(len(plaintext)), start+chunkSize)
		chunks[i] = gcm.Seal(nil, testNonce(prefix, uint32(i)), plaintext[start:end], []byte(cryptobox.ChunkAAD(f.bundle.ID, uploadID, manifest.HeaderSHA256, i)))
	}
	return sealedUpload{manifest: manifest, raw: raw, chunks: chunks}
}

func testNonce(prefix []byte, index uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[8:], index)
	return nonce
}

func request(t *testing.T, f *fixture, method, path, token string, body io.Reader, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, f.server.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "OpaqueDrop "+token)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(response.Body)
	response.Body.Close()
	return response, b
}

func begin(t *testing.T, f *fixture, upload sealedUpload, expected int) {
	t.Helper()
	response, body := request(t, f, http.MethodPost, "/api/v1/requests/"+f.bundle.ID+"/uploads", f.submitToken, bytes.NewReader(upload.raw), map[string]string{"Content-Type": "application/json"})
	if response.StatusCode != expected {
		t.Fatalf("begin status %d, want %d: %s\nlogs: %s", response.StatusCode, expected, body, f.logs.String())
	}
}

func put(t *testing.T, f *fixture, upload sealedUpload, index, expected int) {
	t.Helper()
	path := fmt.Sprintf("/api/v1/requests/%s/uploads/%s/chunks/%d", f.bundle.ID, upload.manifest.UploadID, index)
	response, body := request(t, f, http.MethodPut, path, f.submitToken, bytes.NewReader(upload.chunks[index]), nil)
	if response.StatusCode != expected {
		t.Fatalf("put status %d, want %d: %s", response.StatusCode, expected, body)
	}
}

func complete(t *testing.T, f *fixture, upload sealedUpload, expected int) model.Receipt {
	t.Helper()
	path := fmt.Sprintf("/api/v1/requests/%s/uploads/%s/complete", f.bundle.ID, upload.manifest.UploadID)
	response, body := request(t, f, http.MethodPost, path, f.submitToken, nil, nil)
	if response.StatusCode != expected {
		t.Fatalf("complete status %d, want %d: %s", response.StatusCode, expected, body)
	}
	var receipt model.Receipt
	if expected == http.StatusOK {
		if err := json.Unmarshal(body, &receipt); err != nil {
			t.Fatal(err)
		}
	}
	return receipt
}

func uploadAll(t *testing.T, f *fixture, upload sealedUpload) model.Receipt {
	t.Helper()
	begin(t, f, upload, http.StatusCreated)
	for i := range upload.chunks {
		put(t, f, upload, i, http.StatusNoContent)
	}
	return complete(t, f, upload, http.StatusOK)
}

func TestBrowserCompatibleSuccessAndServerBlindStorage(t *testing.T) {
	f := newFixture(t, 3, 4<<20)
	plaintext := bytes.Repeat([]byte("recipient-only-secret-content|"), 5000)
	upload := seal(t, f, "", plaintext, "../../outside-secret.txt", store.MinChunkSize)
	receipt := uploadAll(t, f, upload)
	if receipt.ReceiptSHA256 == "" || receipt.ChunkCount < 2 {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}

	forbidden := [][]byte{plaintext, []byte("outside-secret.txt"), []byte(f.submitToken), []byte(f.key.CollectToken), []byte(f.key.PrivateKey)}
	err := filepath.Walk(f.root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, value := range forbidden {
			if bytes.Contains(b, value) {
				t.Fatalf("server file %s contains forbidden plaintext or capability", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "received")
	key := f.key
	key.ServerURL = f.server.URL
	results, err := collector.New(key).CollectAll(t.Context(), out, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("collected %d files, want 1", len(results))
	}
	if filepath.Dir(results[0].Path) != out || filepath.Base(results[0].Path) != "outside-secret.txt" {
		t.Fatalf("unsafe output path: %s", results[0].Path)
	}
	got, _ := os.ReadFile(results[0].Path)
	if !bytes.Equal(got, plaintext) {
		t.Fatal("collected plaintext mismatch")
	}
	parts, _ := filepath.Glob(filepath.Join(out, ".opaquedrop-*.part"))
	if len(parts) != 0 {
		t.Fatalf("temporary output files remained: %v", parts)
	}
	receipts, err := collector.New(key).List(t.Context())
	if err != nil || len(receipts) != 1 || !receipts[0].Acknowledged {
		t.Fatalf("acknowledgement not persisted: %+v %v", receipts, err)
	}
}

func TestCapabilitiesOriginQuotaAndMemoryBounds(t *testing.T) {
	f := newFixture(t, 1, 100)
	secret := "raw-token-that-must-not-be-logged"
	response, _ := request(t, f, http.MethodGet, "/api/v1/requests/"+f.bundle.ID, secret, nil, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid capability status = %d", response.StatusCode)
	}
	if strings.Contains(f.logs.String(), secret) {
		t.Fatal("authorization token appeared in server logs")
	}

	valid := seal(t, f, "", []byte("hello"), "safe.txt", store.MinChunkSize)
	response, body := request(t, f, http.MethodPost, "/api/v1/requests/"+f.bundle.ID+"/uploads", f.submitToken, bytes.NewReader(valid.raw), map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
	if response.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte("CROSS_ORIGIN_DENIED")) {
		t.Fatalf("cross-origin request status %d: %s", response.StatusCode, body)
	}

	overQuota := seal(t, f, "", bytes.Repeat([]byte("x"), 101), "too-large.bin", store.MinChunkSize)
	begin(t, f, overQuota, http.StatusRequestEntityTooLarge)

	tooWide := seal(t, f, "", []byte("small"), "wide.bin", store.MaxChunkSize+1)
	begin(t, f, tooWide, http.StatusBadRequest)

	oversizedManifest := bytes.Repeat([]byte(" "), store.MaxManifest+1)
	response, _ = request(t, f, http.MethodPost, "/api/v1/requests/"+f.bundle.ID+"/uploads", f.submitToken, bytes.NewReader(oversizedManifest), nil)
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized manifest status = %d", response.StatusCode)
	}

	begin(t, f, valid, http.StatusCreated)
	second := seal(t, f, "", []byte("second"), "second.txt", store.MinChunkSize)
	begin(t, f, second, http.StatusRequestEntityTooLarge)
	put(t, f, valid, 0, http.StatusNoContent)
	put(t, f, valid, 0, http.StatusConflict)
}

func TestMissingCorruptedAndReorderedChunksFail(t *testing.T) {
	t.Run("missing chunk blocks atomic completion", func(t *testing.T) {
		f := newFixture(t, 2, 1<<20)
		upload := seal(t, f, "", bytes.Repeat([]byte("m"), store.MinChunkSize+10), "missing.bin", store.MinChunkSize)
		begin(t, f, upload, http.StatusCreated)
		put(t, f, upload, 0, http.StatusNoContent)
		complete(t, f, upload, http.StatusConflict)
		completePath := filepath.Join(f.root, "uploads", f.bundle.ID, upload.manifest.UploadID, "complete.json")
		if _, err := os.Stat(completePath); !os.IsNotExist(err) {
			t.Fatalf("completion marker exists after missing chunk: %v", err)
		}
	})

	t.Run("corrupted chunk cannot be collected", func(t *testing.T) {
		f := newFixture(t, 1, 1<<20)
		upload := seal(t, f, "", bytes.Repeat([]byte("c"), store.MinChunkSize+10), "corrupt.bin", store.MinChunkSize)
		uploadAll(t, f, upload)
		chunkPath := filepath.Join(f.root, "uploads", f.bundle.ID, upload.manifest.UploadID, "chunks", "00000000.bin")
		b, _ := os.ReadFile(chunkPath)
		b[len(b)/2] ^= 0x80
		if err := os.WriteFile(chunkPath, b, 0o600); err != nil {
			t.Fatal(err)
		}
		key := f.key
		key.ServerURL = f.server.URL
		out := filepath.Join(t.TempDir(), "out")
		if _, err := collector.New(key).CollectAll(t.Context(), out, false); err == nil || !strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("corrupted collection error = %v", err)
		}
		entries, _ := os.ReadDir(out)
		if len(entries) != 0 {
			t.Fatalf("corrupted upload left output files: %v", entries)
		}
	})

	t.Run("reordered chunks cannot be collected", func(t *testing.T) {
		f := newFixture(t, 1, 1<<20)
		upload := seal(t, f, "", bytes.Repeat([]byte("r"), store.MinChunkSize+10), "reordered.bin", store.MinChunkSize)
		uploadAll(t, f, upload)
		first := filepath.Join(f.root, "uploads", f.bundle.ID, upload.manifest.UploadID, "chunks", "00000000.bin")
		second := filepath.Join(f.root, "uploads", f.bundle.ID, upload.manifest.UploadID, "chunks", "00000001.bin")
		a, _ := os.ReadFile(first)
		b, _ := os.ReadFile(second)
		_ = os.WriteFile(first, b, 0o600)
		_ = os.WriteFile(second, a, 0o600)
		key := f.key
		key.ServerURL = f.server.URL
		if _, err := collector.New(key).CollectAll(t.Context(), filepath.Join(t.TempDir(), "out"), false); err == nil || !strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("reordered collection error = %v", err)
		}
	})
}
