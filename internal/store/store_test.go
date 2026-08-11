package store

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CAOShurong/opaquedrop/internal/core"
	"github.com/CAOShurong/opaquedrop/internal/cryptobox"
	"github.com/CAOShurong/opaquedrop/internal/model"
)

func TestBeginUploadRejectsUnsafeRequestIDBeforeFilesystemAccess(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root", "data")
	s := New(root)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	bundle, _, err := core.MakeRequest("http://127.0.0.1:8080", "test", now, now.Add(time.Hour), 2, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	validRequestID := bundle.ID
	bundle.ID = filepath.Join("..", "..", "escaped-request")

	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := model.Manifest{
		Version:            model.ProtocolVersion,
		Algorithm:          model.Algorithm,
		RequestID:          bundle.ID,
		UploadID:           "abcdefghijklmnopqrstuv",
		PlainSize:          1,
		ChunkSize:          MinChunkSize,
		ChunkCount:         1,
		EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		Salt:               base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		NoncePrefix:        base64.RawURLEncoding.EncodeToString(make([]byte, 8)),
		EncryptedMetadata:  base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	manifest.HeaderSHA256 = cryptobox.HeaderSHA256(manifest)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.BeginUpload(bundle, raw)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("BeginUpload error = %v, want ErrInvalid", err)
	}
	escaped := filepath.Join(filepath.Dir(filepath.Dir(root)), "escaped-request")
	if _, statErr := os.Stat(escaped); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unsafe request created path outside the data root: %s", escaped)
	}

	bundle.ID = validRequestID
	manifest.RequestID = validRequestID
	manifest.UploadID = filepath.Join("..", "..", "escaped-upload")
	manifest.HeaderSHA256 = cryptobox.HeaderSHA256(manifest)
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.BeginUpload(bundle, raw)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("BeginUpload unsafe upload ID error = %v, want ErrInvalid", err)
	}
	escaped = filepath.Join(root, "escaped-upload")
	if _, statErr := os.Stat(escaped); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unsafe upload created path outside the request directory: %s", escaped)
	}
}
