package cryptobox

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/CAOShurong/opaquedrop/internal/model"
)

type protocolVector struct {
	VectorVersion       int      `json:"vector_version"`
	RecipientPrivateKey string   `json:"recipient_private_key"`
	RecipientPublicKey  string   `json:"recipient_public_key"`
	ManifestJSON        string   `json:"manifest_json"`
	CiphertextChunks    []string `json:"ciphertext_chunks"`
	Plaintext           string   `json:"plaintext_base64url"`
	MetadataJSON        string   `json:"metadata_json"`
	NoncesHex           []string `json:"nonces_hex"`
	ReceiptSHA256       string   `json:"receipt_sha256"`
}

func loadVector(t *testing.T) (protocolVector, model.Manifest, model.KeyFile, [][]byte) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/protocol-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector protocolVector
	if err := json.Unmarshal(b, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.VectorVersion != 1 {
		t.Fatalf("unexpected vector version %d", vector.VectorVersion)
	}
	var manifest model.Manifest
	if err := json.Unmarshal([]byte(vector.ManifestJSON), &manifest); err != nil {
		t.Fatal(err)
	}
	chunks := make([][]byte, len(vector.CiphertextChunks))
	for i, encoded := range vector.CiphertextChunks {
		chunks[i], err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
	}
	key := model.KeyFile{SchemaVersion: 1, RequestID: manifest.RequestID, PrivateKey: vector.RecipientPrivateKey, PublicKey: vector.RecipientPublicKey}
	return vector, manifest, key, chunks
}

func TestNodeWebCryptoVectorOpensInGo(t *testing.T) {
	vector, manifest, key, chunks := loadVector(t)
	if got := HeaderSHA256(manifest); got != manifest.HeaderSHA256 {
		t.Fatalf("header hash = %s, want %s", got, manifest.HeaderSHA256)
	}
	opener, err := NewOpener(key, manifest)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := opener.Metadata(manifest.EncryptedMetadata)
	if err != nil {
		t.Fatal(err)
	}
	metadataBytes, _ := json.Marshal(metadata)
	if string(metadataBytes) != vector.MetadataJSON {
		t.Fatalf("metadata = %s, want %s", metadataBytes, vector.MetadataJSON)
	}
	var plaintext []byte
	chunkDigests := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		part, err := opener.Chunk(i, chunk)
		if err != nil {
			t.Fatalf("open chunk %d: %v", i, err)
		}
		plaintext = append(plaintext, part...)
		sum := sha256.Sum256(chunk)
		chunkDigests[i] = append([]byte(nil), sum[:]...)
	}
	wantPlain, _ := base64.RawURLEncoding.DecodeString(vector.Plaintext)
	if string(plaintext) != string(wantPlain) {
		t.Fatal("plaintext mismatch")
	}
	if got := ReceiptRoot([]byte(vector.ManifestJSON), chunkDigests); got != vector.ReceiptSHA256 {
		t.Fatalf("receipt = %s, want %s", got, vector.ReceiptSHA256)
	}
}

func TestProtocolNonceSeparation(t *testing.T) {
	vector, _, _, _ := loadVector(t)
	seen := map[string]bool{}
	for _, value := range vector.NoncesHex {
		if _, err := hex.DecodeString(value); err != nil || len(value) != 24 {
			t.Fatalf("invalid nonce %q", value)
		}
		if seen[value] {
			t.Fatalf("nonce reused: %s", value)
		}
		seen[value] = true
	}
	if !strings.HasSuffix(vector.NoncesHex[0], "ffffffff") {
		t.Fatalf("metadata nonce does not use reserved index: %s", vector.NoncesHex[0])
	}
}

func TestTamperingAndReorderingFailAuthentication(t *testing.T) {
	_, manifest, key, chunks := loadVector(t)
	opener, err := NewOpener(key, manifest)
	if err != nil {
		t.Fatal(err)
	}
	corrupted := append([]byte(nil), chunks[0]...)
	corrupted[len(corrupted)/2] ^= 0x40
	if _, err := opener.Chunk(0, corrupted); err == nil {
		t.Fatal("corrupted ciphertext authenticated")
	}
	if _, err := opener.Chunk(0, chunks[1]); err == nil {
		t.Fatal("reordered ciphertext authenticated at the wrong index")
	}
	metadata, _ := base64.RawURLEncoding.DecodeString(manifest.EncryptedMetadata)
	metadata[0] ^= 1
	if _, err := opener.Metadata(base64.RawURLEncoding.EncodeToString(metadata)); err == nil {
		t.Fatal("corrupted metadata authenticated")
	}
}

func TestManifestFieldsAreBound(t *testing.T) {
	_, manifest, key, _ := loadVector(t)
	mutations := []func(*model.Manifest){
		func(m *model.Manifest) { m.PlainSize++ },
		func(m *model.Manifest) { m.ChunkCount++ },
		func(m *model.Manifest) { m.ChunkSize++ },
		func(m *model.Manifest) { m.NoncePrefix = "AAAAAAAAAAA" },
		func(m *model.Manifest) { m.Salt = strings.Repeat("A", len(m.Salt)) },
		func(m *model.Manifest) { m.EphemeralPublicKey = key.PublicKey },
	}
	for i, mutate := range mutations {
		copy := manifest
		mutate(&copy)
		if _, err := NewOpener(key, copy); err == nil {
			t.Fatalf("mutation %d was not rejected", i)
		}
	}
}
