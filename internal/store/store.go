package store

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CAOShurong/opaquedrop/internal/core"
	"github.com/CAOShurong/opaquedrop/internal/cryptobox"
	"github.com/CAOShurong/opaquedrop/internal/model"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrExpired  = errors.New("request expired")
	ErrClosed   = errors.New("request closed")
	ErrQuota    = errors.New("request quota exceeded")
	ErrInvalid  = errors.New("invalid input")
)

const (
	MinChunkSize = 64 << 10
	MaxChunkSize = 8 << 20
	MaxManifest  = 64 << 10
)

type Store struct {
	Root string
	mu   sync.Mutex
	now  func() time.Time
}

type PurgeResult struct {
	UploadDirs []string `json:"upload_dirs"`
	Bytes      int64    `json:"bytes"`
}

func New(root string) *Store {
	return &Store{Root: filepath.Clean(root), now: time.Now}
}

func (s *Store) SetClock(now func() time.Time) { s.now = now }

func (s *Store) Init() error {
	for _, dir := range []string{s.Root, s.requestsDir(), s.closedRequestsDir(), s.uploadsDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		_ = os.Chmod(dir, 0o700)
	}
	marker := filepath.Join(s.Root, "opaquedrop.json")
	if _, err := os.Stat(marker); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b, _ := core.MarshalPretty(map[string]any{"schema_version": model.SchemaVersion, "created_at": s.now().UTC()})
	return writeNew(marker, b, 0o600)
}

func (s *Store) Doctor() ([]string, error) {
	var checks []string
	info, err := os.Stat(s.Root)
	if err != nil {
		return checks, fmt.Errorf("data directory: %w", err)
	}
	if !info.IsDir() {
		return checks, errors.New("data path is not a directory")
	}
	checks = append(checks, "data directory exists")
	if link, err := os.Lstat(s.Root); err == nil && link.Mode()&os.ModeSymlink != 0 {
		return checks, errors.New("data directory must not be a symbolic link")
	}
	checks = append(checks, "data directory is not a symlink")
	for _, p := range []string{filepath.Join(s.Root, "opaquedrop.json"), s.requestsDir(), s.closedRequestsDir(), s.uploadsDir()} {
		if _, err := os.Stat(p); err != nil {
			return checks, fmt.Errorf("required path %s: %w", p, err)
		}
	}
	checks = append(checks, "state marker and storage directories exist")
	return checks, nil
}

func (s *Store) ImportRequest(bundle model.RequestBundle) error {
	if err := validateBundle(bundle); err != nil {
		return err
	}
	if err := s.Init(); err != nil {
		return err
	}
	b, err := core.MarshalPretty(bundle)
	if err != nil {
		return err
	}
	err = writeNew(s.requestPath(bundle.ID), b, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrConflict
	}
	return err
}

func (s *Store) Request(id string) (model.RequestBundle, error) {
	return s.readRequestPath(id, s.requestPath(id))
}

// RequestIncludingClosed loads a request for recipient-side collection. New
// submission paths must use Request or explicitly check Closed while holding
// the store mutex.
func (s *Store) RequestIncludingClosed(id string) (model.RequestBundle, error) {
	bundle, err := s.Request(id)
	if err == nil || !errors.Is(err, ErrNotFound) {
		return bundle, err
	}
	return s.readRequestPath(id, s.closedRequestPath(id))
}

func (s *Store) readRequestPath(id, path string) (model.RequestBundle, error) {
	if !core.ValidID(id) {
		return model.RequestBundle{}, ErrNotFound
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return model.RequestBundle{}, ErrNotFound
	}
	if err != nil {
		return model.RequestBundle{}, err
	}
	var bundle model.RequestBundle
	if err := json.Unmarshal(b, &bundle); err != nil {
		return model.RequestBundle{}, err
	}
	return bundle, nil
}

// Closed reports whether a durable closure marker exists. Marker presence is
// deliberately fail-closed even if later inspection finds malformed content.
func (s *Store) Closed(id string) (bool, error) {
	if !core.ValidID(id) {
		return false, ErrNotFound
	}
	_, err := os.Stat(s.closurePath(id))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// CloseRequest irreversibly stops new submit-side mutations. The closure
// marker is written before the active bundle is moved so a failed rename still
// leaves new binaries fail-closed and a later call can finish the transition.
func (s *Store) CloseRequest(id string) (model.RequestClosure, error) {
	if !core.ValidID(id) {
		return model.RequestClosure{}, ErrNotFound
	}
	if err := s.Init(); err != nil {
		return model.RequestClosure{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	closure, closureErr := s.readClosure(id)
	if closureErr != nil && !errors.Is(closureErr, ErrNotFound) {
		return model.RequestClosure{}, closureErr
	}
	activePath := s.requestPath(id)
	closedPath := s.closedRequestPath(id)
	_, activeErr := os.Stat(activePath)
	_, closedErr := os.Stat(closedPath)
	activeExists := activeErr == nil
	closedExists := closedErr == nil
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return model.RequestClosure{}, activeErr
	}
	if closedErr != nil && !errors.Is(closedErr, os.ErrNotExist) {
		return model.RequestClosure{}, closedErr
	}
	if !activeExists && !closedExists {
		return model.RequestClosure{}, ErrNotFound
	}
	if activeExists && closedExists {
		return model.RequestClosure{}, ErrConflict
	}

	if errors.Is(closureErr, ErrNotFound) {
		closure = model.RequestClosure{SchemaVersion: model.SchemaVersion, RequestID: id, ClosedAt: s.now().UTC()}
		encoded, err := core.MarshalPretty(closure)
		if err != nil {
			return model.RequestClosure{}, err
		}
		writeErr := writeNew(s.closurePath(id), encoded, 0o600)
		if writeErr != nil && !errors.Is(writeErr, os.ErrExist) {
			return model.RequestClosure{}, writeErr
		}
		if errors.Is(writeErr, os.ErrExist) {
			var err error
			closure, err = s.readClosure(id)
			if err != nil {
				return model.RequestClosure{}, err
			}
		}
	}
	if activeExists {
		if err := os.Rename(activePath, closedPath); err != nil {
			return model.RequestClosure{}, err
		}
		if err := os.Chmod(closedPath, 0o600); err != nil {
			return model.RequestClosure{}, err
		}
	}
	return closure, nil
}

func (s *Store) readClosure(id string) (model.RequestClosure, error) {
	b, err := os.ReadFile(s.closurePath(id))
	if errors.Is(err, os.ErrNotExist) {
		return model.RequestClosure{}, ErrNotFound
	}
	if err != nil {
		return model.RequestClosure{}, err
	}
	var closure model.RequestClosure
	if err := json.Unmarshal(b, &closure); err != nil {
		return model.RequestClosure{}, err
	}
	if closure.SchemaVersion != model.SchemaVersion || closure.RequestID != id || closure.ClosedAt.IsZero() {
		return model.RequestClosure{}, fmt.Errorf("%w: closure record", ErrInvalid)
	}
	return closure, nil
}

func (s *Store) Authenticate(id, token, kind string) (model.RequestBundle, bool) {
	bundle, err := s.RequestIncludingClosed(id)
	if err != nil || token == "" {
		return model.RequestBundle{}, false
	}
	wantHex := bundle.SubmitTokenHash
	if kind == "collect" {
		wantHex = bundle.CollectTokenHash
	}
	want, err := hex.DecodeString(wantHex)
	if err != nil || len(want) != sha256.Size {
		return model.RequestBundle{}, false
	}
	got := sha256.Sum256([]byte(token))
	return bundle, subtle.ConstantTimeCompare(got[:], want) == 1
}

func (s *Store) Info(bundle model.RequestBundle) (model.RequestInfo, error) {
	if err := validateBundle(bundle); err != nil {
		return model.RequestInfo{}, err
	}
	files, bytes, err := s.usage(bundle.ID)
	if err != nil {
		return model.RequestInfo{}, err
	}
	return model.RequestInfo{
		ID: bundle.ID, Label: bundle.Label, ExpiresAt: bundle.ExpiresAt,
		MaxFiles: bundle.MaxFiles, MaxBytes: bundle.MaxBytes, UsedFiles: files, UsedBytes: bytes,
		PublicKey: bundle.PublicKey, Algorithm: model.Algorithm,
	}, nil
}

func (s *Store) BeginUpload(bundle model.RequestBundle, raw []byte) (model.Manifest, error) {
	if err := validateBundle(bundle); err != nil {
		return model.Manifest{}, err
	}
	if len(raw) == 0 || len(raw) > MaxManifest {
		return model.Manifest{}, fmt.Errorf("%w: manifest size", ErrInvalid)
	}
	var manifest model.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return manifest, fmt.Errorf("%w: invalid manifest JSON", ErrInvalid)
	}
	if manifest.PlainSize > bundle.MaxBytes {
		return manifest, ErrQuota
	}
	if err := validateManifest(bundle, manifest); err != nil {
		return manifest, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if closed, err := s.Closed(bundle.ID); err != nil {
		return manifest, err
	} else if closed {
		return manifest, ErrClosed
	}
	if !bundle.ExpiresAt.After(s.now()) {
		return manifest, ErrExpired
	}
	// Keep both identifiers as single path components at the filesystem boundary.
	// validateBundle and validateManifest already enforce a stricter allow list; the
	// explicit separator checks make that invariant local to the path operation.
	if strings.Contains(bundle.ID, "/") || strings.Contains(bundle.ID, "\\") || strings.Contains(bundle.ID, "..") ||
		strings.Contains(manifest.UploadID, "/") || strings.Contains(manifest.UploadID, "\\") || strings.Contains(manifest.UploadID, "..") {
		return manifest, fmt.Errorf("%w: upload path components", ErrInvalid)
	}
	uploadRelative := filepath.Join(bundle.ID, manifest.UploadID)
	uploadDir := filepath.Join(s.uploadsDir(), bundle.ID, manifest.UploadID)
	uploadsRoot, err := os.OpenRoot(s.uploadsDir())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return manifest, err
	}
	if uploadsRoot != nil {
		defer uploadsRoot.Close()
	}
	if info, err := uploadsRootLstat(uploadsRoot, uploadRelative); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return manifest, ErrConflict
		}
		existing, err := uploadsRoot.ReadFile(filepath.Join(uploadRelative, "manifest.json"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return manifest, ErrConflict
			}
			return manifest, err
		}
		if subtle.ConstantTimeCompare(existing, raw) != 1 {
			return manifest, ErrConflict
		}
		stateBytes, err := uploadsRoot.ReadFile(filepath.Join(uploadRelative, "server.json"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return manifest, ErrConflict
			}
			return manifest, err
		}
		var state model.UploadServerState
		if err := json.Unmarshal(stateBytes, &state); err != nil {
			return manifest, err
		}
		chunks, err := uploadsRoot.Lstat(filepath.Join(uploadRelative, "chunks"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return manifest, ErrConflict
			}
			return manifest, err
		}
		if !chunks.IsDir() || chunks.Mode()&os.ModeSymlink != 0 || state.CreatedAt.IsZero() ||
			state.RequestID != bundle.ID || state.UploadID != manifest.UploadID || state.PlainSize != manifest.PlainSize ||
			state.ChunkSize != manifest.ChunkSize || state.ChunkCount != manifest.ChunkCount {
			return manifest, ErrConflict
		}
		return manifest, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return manifest, err
	}
	files, bytes, err := s.usage(bundle.ID)
	if err != nil {
		return manifest, err
	}
	if files >= bundle.MaxFiles || manifest.PlainSize > bundle.MaxBytes-bytes {
		return manifest, ErrQuota
	}
	requestUploadDir := filepath.Join(s.uploadsDir(), filepath.Base(bundle.ID))
	if err := os.MkdirAll(requestUploadDir, 0o700); err != nil {
		return manifest, err
	}
	// Keep the standard-library basename sanitizers at this filesystem boundary.
	// validateBundle and validateManifest reject altered components before this point.
	if err := os.Mkdir(uploadDir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return manifest, ErrConflict
		}
		return manifest, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(uploadDir)
		}
	}()
	if err := os.Mkdir(filepath.Join(uploadDir, "chunks"), 0o700); err != nil {
		return manifest, err
	}
	if err := writeNew(filepath.Join(uploadDir, "manifest.json"), raw, 0o600); err != nil {
		return manifest, err
	}
	state := model.UploadServerState{RequestID: bundle.ID, UploadID: manifest.UploadID, CreatedAt: s.now().UTC(), PlainSize: manifest.PlainSize, ChunkSize: manifest.ChunkSize, ChunkCount: manifest.ChunkCount}
	stateBytes, _ := core.MarshalPretty(state)
	if err := writeNew(filepath.Join(uploadDir, "server.json"), stateBytes, 0o600); err != nil {
		return manifest, err
	}
	cleanup = false
	return manifest, nil
}

func uploadsRootLstat(root *os.Root, name string) (os.FileInfo, error) {
	if root == nil {
		return nil, os.ErrNotExist
	}
	return root.Lstat(name)
}

func (s *Store) PutChunk(requestID, uploadID string, index int, r io.Reader, contentLength int64) error {
	manifest, _, err := s.readManifest(requestID, uploadID)
	if err != nil {
		return err
	}
	if index < 0 || index >= manifest.ChunkCount {
		return fmt.Errorf("%w: chunk index", ErrInvalid)
	}
	expected := expectedCipherChunkSize(manifest, index)
	if contentLength >= 0 && contentLength != expected {
		return fmt.Errorf("%w: chunk length", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if closed, err := s.Closed(requestID); err != nil {
		return err
	} else if closed {
		return ErrClosed
	}
	dest := s.chunkPath(requestID, uploadID, index)
	if _, err := os.Stat(dest); err == nil {
		return ErrConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(dest), ".chunk-*.part")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	_ = temp.Chmod(0o600)
	written, copyErr := io.Copy(temp, io.LimitReader(r, expected+1))
	closeErr := temp.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != expected {
		return fmt.Errorf("%w: chunk length", ErrInvalid)
	}
	if err := os.Rename(tempName, dest); err != nil {
		if _, statErr := os.Stat(dest); statErr == nil {
			return ErrConflict
		}
		return err
	}
	return nil
}

func (s *Store) ChunkDigest(requestID, uploadID string, index int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if closed, err := s.Closed(requestID); err != nil {
		return "", err
	} else if closed {
		return "", ErrClosed
	}
	manifest, _, err := s.readManifest(requestID, uploadID)
	if err != nil || index < 0 || index >= manifest.ChunkCount {
		return "", ErrNotFound
	}
	f, err := os.Open(s.chunkPath(requestID, uploadID, index))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Store) Complete(requestID, uploadID string) (model.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if closed, err := s.Closed(requestID); err != nil {
		return model.Receipt{}, err
	} else if closed {
		return model.Receipt{}, ErrClosed
	}
	if receipt, err := s.readReceipt(requestID, uploadID); err == nil {
		return receipt, nil
	}
	manifest, raw, err := s.readManifest(requestID, uploadID)
	if err != nil {
		return model.Receipt{}, err
	}
	digests := make([][]byte, manifest.ChunkCount)
	var cipherBytes int64
	for i := 0; i < manifest.ChunkCount; i++ {
		path := s.chunkPath(requestID, uploadID, i)
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			return model.Receipt{}, fmt.Errorf("%w: missing chunk %d", ErrConflict, i)
		}
		if err != nil {
			return model.Receipt{}, err
		}
		if info.Size() != expectedCipherChunkSize(manifest, i) {
			return model.Receipt{}, fmt.Errorf("%w: invalid chunk %d size", ErrConflict, i)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return model.Receipt{}, err
		}
		sum := sha256.Sum256(b)
		digests[i] = append([]byte(nil), sum[:]...)
		cipherBytes += int64(len(b))
	}
	receipt := model.Receipt{
		Version: 1, RequestID: requestID, UploadID: uploadID, CompletedAt: s.now().UTC(),
		PlainSize: manifest.PlainSize, CipherBytes: cipherBytes, ChunkCount: manifest.ChunkCount,
		ReceiptSHA256: cryptobox.ReceiptRoot(raw, digests),
	}
	b, _ := core.MarshalPretty(receipt)
	if err := writeNew(s.completePath(requestID, uploadID), b, 0o600); err != nil {
		if errors.Is(err, os.ErrExist) {
			return s.readReceipt(requestID, uploadID)
		}
		return model.Receipt{}, err
	}
	return receipt, nil
}

func (s *Store) ListReceipts(requestID string) ([]model.Receipt, error) {
	if !core.ValidID(requestID) {
		return nil, ErrInvalid
	}
	dir := filepath.Join(s.uploadsDir(), filepath.Base(requestID))
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []model.Receipt{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]model.Receipt, 0)
	for _, entry := range entries {
		if !entry.IsDir() || !core.ValidID(entry.Name()) {
			continue
		}
		receipt, err := s.readReceipt(requestID, entry.Name())
		if err != nil {
			continue
		}
		_, ackErr := os.Stat(s.ackPath(requestID, entry.Name()))
		receipt.Acknowledged = ackErr == nil
		result = append(result, receipt)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CompletedAt.Before(result[j].CompletedAt) })
	return result, nil
}

func (s *Store) ReadManifest(requestID, uploadID string) ([]byte, error) {
	_, raw, err := s.readManifest(requestID, uploadID)
	return raw, err
}

func (s *Store) OpenChunk(requestID, uploadID string, index int) (*os.File, int64, error) {
	manifest, _, err := s.readManifest(requestID, uploadID)
	if err != nil || index < 0 || index >= manifest.ChunkCount {
		return nil, 0, ErrNotFound
	}
	if _, err := s.readReceipt(requestID, uploadID); err != nil {
		return nil, 0, ErrNotFound
	}
	f, err := os.Open(s.chunkPath(requestID, uploadID, index))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

func (s *Store) Acknowledge(bundle model.RequestBundle, uploadID string) error {
	if err := validateBundle(bundle); err != nil || !core.ValidID(uploadID) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.readReceipt(bundle.ID, uploadID); err != nil {
		return ErrNotFound
	}
	b, _ := core.MarshalPretty(map[string]any{"acknowledged_at": s.now().UTC()})
	err := writeNew(s.ackPath(bundle.ID, uploadID), b, 0o600)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if bundle.DeleteAfterCollect {
		return os.RemoveAll(s.uploadDir(bundle.ID, uploadID))
	}
	return nil
}

func (s *Store) Purge(apply bool, staleIncomplete time.Duration) (PurgeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := PurgeResult{}
	requests, err := os.ReadDir(s.uploadsDir())
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	for _, requestEntry := range requests {
		if !requestEntry.IsDir() || !core.ValidID(requestEntry.Name()) {
			continue
		}
		bundle, bundleErr := s.RequestIncludingClosed(requestEntry.Name())
		uploads, _ := os.ReadDir(filepath.Join(s.uploadsDir(), requestEntry.Name()))
		for _, upload := range uploads {
			if !upload.IsDir() || !core.ValidID(upload.Name()) {
				continue
			}
			dir := s.uploadDir(requestEntry.Name(), upload.Name())
			state, stateErr := s.readServerState(requestEntry.Name(), upload.Name())
			expired := bundleErr != nil || !bundle.ExpiresAt.After(s.now())
			stale := stateErr != nil || (s.now().Sub(state.CreatedAt) > staleIncomplete && !fileExists(s.completePath(requestEntry.Name(), upload.Name())))
			if !expired && !stale {
				continue
			}
			result.UploadDirs = append(result.UploadDirs, dir)
			result.Bytes += dirSize(dir)
			if apply {
				if err := os.RemoveAll(dir); err != nil {
					return result, err
				}
			}
		}
	}
	return result, nil
}

func (s *Store) usage(requestID string) (int, int64, error) {
	if !core.ValidID(requestID) {
		return 0, 0, ErrInvalid
	}
	dir := filepath.Join(s.uploadsDir(), filepath.Base(requestID))
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	var files int
	var bytes int64
	for _, entry := range entries {
		if !entry.IsDir() || !core.ValidID(entry.Name()) {
			continue
		}
		state, err := s.readServerState(requestID, entry.Name())
		if err == nil {
			files++
			bytes += state.PlainSize
		}
	}
	return files, bytes, nil
}

func (s *Store) readManifest(requestID, uploadID string) (model.Manifest, []byte, error) {
	if !core.ValidID(requestID) || !core.ValidID(uploadID) {
		return model.Manifest{}, nil, ErrNotFound
	}
	b, err := os.ReadFile(filepath.Join(s.uploadDir(requestID, uploadID), "manifest.json"))
	if errors.Is(err, os.ErrNotExist) {
		return model.Manifest{}, nil, ErrNotFound
	}
	if err != nil {
		return model.Manifest{}, nil, err
	}
	var manifest model.Manifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		return model.Manifest{}, nil, err
	}
	return manifest, b, nil
}

func (s *Store) readServerState(requestID, uploadID string) (model.UploadServerState, error) {
	b, err := os.ReadFile(filepath.Join(s.uploadDir(requestID, uploadID), "server.json"))
	if err != nil {
		return model.UploadServerState{}, err
	}
	var state model.UploadServerState
	err = json.Unmarshal(b, &state)
	return state, err
}

func (s *Store) readReceipt(requestID, uploadID string) (model.Receipt, error) {
	b, err := os.ReadFile(s.completePath(requestID, uploadID))
	if errors.Is(err, os.ErrNotExist) {
		return model.Receipt{}, ErrNotFound
	}
	if err != nil {
		return model.Receipt{}, err
	}
	var receipt model.Receipt
	err = json.Unmarshal(b, &receipt)
	return receipt, err
}

func validateBundle(bundle model.RequestBundle) error {
	if bundle.SchemaVersion != model.SchemaVersion || !core.ValidID(bundle.ID) {
		return fmt.Errorf("%w: bundle version or id", ErrInvalid)
	}
	if strings.TrimSpace(bundle.Label) == "" || len(bundle.Label) > 120 || !bundle.ExpiresAt.After(bundle.CreatedAt) {
		return fmt.Errorf("%w: bundle metadata", ErrInvalid)
	}
	if bundle.MaxFiles < 1 || bundle.MaxFiles > 10_000 || bundle.MaxBytes < 1 || bundle.MaxBytes > 1<<50 {
		return fmt.Errorf("%w: bundle quota", ErrInvalid)
	}
	publicBytes, err := base64.RawURLEncoding.DecodeString(bundle.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: public key", ErrInvalid)
	}
	if _, err := ecdh.P256().NewPublicKey(publicBytes); err != nil {
		return fmt.Errorf("%w: public key", ErrInvalid)
	}
	for _, value := range []string{bundle.SubmitTokenHash, bundle.CollectTokenHash} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("%w: token hash", ErrInvalid)
		}
	}
	return nil
}

func validateManifest(bundle model.RequestBundle, m model.Manifest) error {
	if m.Version != model.ProtocolVersion || m.Algorithm != model.Algorithm || m.RequestID != bundle.ID || !core.ValidID(m.UploadID) {
		return fmt.Errorf("%w: protocol fields", ErrInvalid)
	}
	if m.PlainSize < 0 || m.PlainSize > bundle.MaxBytes || m.ChunkSize < MinChunkSize || m.ChunkSize > MaxChunkSize {
		return fmt.Errorf("%w: sizes", ErrInvalid)
	}
	expectedChunks := int((m.PlainSize + m.ChunkSize - 1) / m.ChunkSize)
	if expectedChunks == 0 {
		expectedChunks = 1
	}
	if m.ChunkCount != expectedChunks || m.ChunkCount < 1 || uint64(m.ChunkCount) >= uint64(^uint32(0)) {
		return fmt.Errorf("%w: chunk count", ErrInvalid)
	}
	pub, err := base64.RawURLEncoding.DecodeString(m.EphemeralPublicKey)
	if err != nil {
		return fmt.Errorf("%w: ephemeral key", ErrInvalid)
	}
	if _, err := ecdh.P256().NewPublicKey(pub); err != nil {
		return fmt.Errorf("%w: ephemeral key", ErrInvalid)
	}
	salt, err1 := base64.RawURLEncoding.DecodeString(m.Salt)
	nonce, err2 := base64.RawURLEncoding.DecodeString(m.NoncePrefix)
	metadata, err3 := base64.RawURLEncoding.DecodeString(m.EncryptedMetadata)
	header, err4 := hex.DecodeString(m.HeaderSHA256)
	if err1 != nil || len(salt) != 32 || err2 != nil || len(nonce) != 8 || err3 != nil || len(metadata) < 16 || len(metadata) > 16<<10 || err4 != nil || len(header) != sha256.Size {
		return fmt.Errorf("%w: encryption parameters", ErrInvalid)
	}
	if !strings.EqualFold(m.HeaderSHA256, cryptobox.HeaderSHA256(m)) {
		return fmt.Errorf("%w: manifest header binding", ErrInvalid)
	}
	return nil
}

func expectedCipherChunkSize(m model.Manifest, index int) int64 {
	plain := m.ChunkSize
	if index == m.ChunkCount-1 {
		plain = m.PlainSize - int64(index)*m.ChunkSize
	}
	return plain + 16
}

func writeNew(path string, data []byte, perm os.FileMode) error {
	if _, err := os.Stat(path); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".opaquedrop-state-*.part")
	if err != nil {
		return err
	}
	tempName := f.Name()
	_ = f.Chmod(perm)
	defer func() {
		_ = f.Close()
		_ = os.Remove(tempName)
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		if _, statErr := os.Stat(path); statErr == nil {
			return os.ErrExist
		}
		return err
	}
	return os.Chmod(path, perm)
}

func (s *Store) requestsDir() string       { return filepath.Join(s.Root, "requests") }
func (s *Store) closedRequestsDir() string { return filepath.Join(s.Root, "closed-requests") }
func (s *Store) uploadsDir() string        { return filepath.Join(s.Root, "uploads") }
func (s *Store) requestPath(id string) string {
	return filepath.Join(s.requestsDir(), filepath.Base(id)+".json")
}
func (s *Store) closedRequestPath(id string) string {
	return filepath.Join(s.closedRequestsDir(), filepath.Base(id)+".json")
}
func (s *Store) closurePath(id string) string {
	return filepath.Join(s.closedRequestsDir(), filepath.Base(id)+".closure.json")
}
func (s *Store) uploadDir(requestID, uploadID string) string {
	return filepath.Join(s.uploadsDir(), filepath.Base(requestID), filepath.Base(uploadID))
}
func (s *Store) chunkPath(requestID, uploadID string, index int) string {
	return filepath.Join(s.uploadDir(requestID, uploadID), "chunks", fmt.Sprintf("%08d.bin", index))
}
func (s *Store) completePath(requestID, uploadID string) string {
	return filepath.Join(s.uploadDir(requestID, uploadID), "complete.json")
}
func (s *Store) ackPath(requestID, uploadID string) string {
	return filepath.Join(s.uploadDir(requestID, uploadID), "acknowledged.json")
}

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }

func dirSize(root string) int64 {
	var total int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

func ParseChunkIndex(value string) (int, error) {
	if value == "" || len(value) > 10 {
		return 0, ErrInvalid
	}
	i, err := strconv.Atoi(value)
	if err != nil || i < 0 {
		return 0, ErrInvalid
	}
	return i, nil
}
