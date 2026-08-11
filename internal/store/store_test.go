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

func TestCloseRequestMovesBundleAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	s := New(root)
	now := time.Date(2026, time.August, 11, 20, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	bundle, _, err := core.MakeRequest("http://127.0.0.1:8080", "close test", now, now.Add(time.Hour), 2, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ImportRequest(bundle); err != nil {
		t.Fatal(err)
	}

	closure, err := s.CloseRequest(bundle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if closure.SchemaVersion != model.SchemaVersion || closure.RequestID != bundle.ID || !closure.ClosedAt.Equal(now) {
		t.Fatalf("closure = %+v", closure)
	}
	if _, err := s.Request(bundle.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("active Request error = %v, want ErrNotFound", err)
	}
	reopened := New(root)
	closedBundle, err := reopened.RequestIncludingClosed(bundle.ID)
	if err != nil || closedBundle.ID != bundle.ID {
		t.Fatalf("RequestIncludingClosed = %+v, %v", closedBundle, err)
	}
	closed, err := reopened.Closed(bundle.ID)
	if err != nil || !closed {
		t.Fatalf("Closed = %v, %v", closed, err)
	}
	if _, err := os.Stat(s.closedRequestPath(bundle.ID)); err != nil {
		t.Fatalf("closed bundle: %v", err)
	}
	if _, err := os.Stat(s.closurePath(bundle.ID)); err != nil {
		t.Fatalf("closure marker: %v", err)
	}

	now = now.Add(10 * time.Minute)
	again, err := s.CloseRequest(bundle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !again.ClosedAt.Equal(closure.ClosedAt) {
		t.Fatalf("idempotent close changed timestamp: first=%s second=%s", closure.ClosedAt, again.ClosedAt)
	}
	if _, err := s.CloseRequest("missing-request-id-1234"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("close missing request error = %v, want ErrNotFound", err)
	}
}

func TestCloseRequestFinishesInterruptedMove(t *testing.T) {
	root := t.TempDir()
	s := New(root)
	now := time.Date(2026, time.August, 11, 21, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	bundle, _, err := core.MakeRequest("http://127.0.0.1:8080", "interrupted close", now, now.Add(time.Hour), 1, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ImportRequest(bundle); err != nil {
		t.Fatal(err)
	}
	closure := model.RequestClosure{SchemaVersion: model.SchemaVersion, RequestID: bundle.ID, ClosedAt: now}
	encoded, err := core.MarshalPretty(closure)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNew(s.closurePath(bundle.ID), encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	now = now.Add(time.Minute)
	finished, err := s.CloseRequest(bundle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !finished.ClosedAt.Equal(closure.ClosedAt) {
		t.Fatalf("recovered close time = %s, want %s", finished.ClosedAt, closure.ClosedAt)
	}
	if _, err := os.Stat(s.requestPath(bundle.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active bundle remains after recovery: %v", err)
	}
	if _, err := os.Stat(s.closedRequestPath(bundle.ID)); err != nil {
		t.Fatalf("closed bundle after recovery: %v", err)
	}
}
