package model

import "time"

const (
	SchemaVersion   = 1
	ProtocolVersion = 1
	Algorithm       = "ECDH-P256+HKDF-SHA256+AES-256-GCM-CHUNKED"
)

// RequestBundle is safe to copy to the server. It never contains a raw
// capability token or recipient private key.
type RequestBundle struct {
	SchemaVersion      int       `json:"schema_version"`
	ID                 string    `json:"id"`
	Label              string    `json:"label"`
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	MaxFiles           int       `json:"max_files"`
	MaxBytes           int64     `json:"max_bytes"`
	DeleteAfterCollect bool      `json:"delete_after_collect"`
	PublicKey          string    `json:"public_key"`
	SubmitTokenHash    string    `json:"submit_token_hash"`
	CollectTokenHash   string    `json:"collect_token_hash"`
}

// KeyFile belongs on a recipient-controlled device. The server does not need it.
type KeyFile struct {
	SchemaVersion int       `json:"schema_version"`
	RequestID     string    `json:"request_id"`
	Label         string    `json:"label"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	ServerURL     string    `json:"server_url"`
	SubmitURL     string    `json:"submit_url"`
	CollectToken  string    `json:"collect_token"`
	PrivateKey    string    `json:"private_key"`
	PublicKey     string    `json:"public_key"`
}

// Manifest contains only encrypted metadata plus the minimum information
// required to store and decrypt framed ciphertext.
type Manifest struct {
	Version            int    `json:"version"`
	RequestID          string `json:"request_id"`
	UploadID           string `json:"upload_id"`
	Algorithm          string `json:"algorithm"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Salt               string `json:"salt"`
	NoncePrefix        string `json:"nonce_prefix"`
	ChunkSize          int64  `json:"chunk_size"`
	ChunkCount         int    `json:"chunk_count"`
	PlainSize          int64  `json:"plain_size"`
	HeaderSHA256       string `json:"header_sha256"`
	EncryptedMetadata  string `json:"encrypted_metadata"`
}

type FileMetadata struct {
	Name         string `json:"name"`
	Type         string `json:"type,omitempty"`
	LastModified int64  `json:"last_modified,omitempty"`
}

type UploadServerState struct {
	RequestID  string    `json:"request_id"`
	UploadID   string    `json:"upload_id"`
	CreatedAt  time.Time `json:"created_at"`
	PlainSize  int64     `json:"plain_size"`
	ChunkSize  int64     `json:"chunk_size"`
	ChunkCount int       `json:"chunk_count"`
}

type Receipt struct {
	Version       int       `json:"version"`
	RequestID     string    `json:"request_id"`
	UploadID      string    `json:"upload_id"`
	CompletedAt   time.Time `json:"completed_at"`
	PlainSize     int64     `json:"plain_size"`
	CipherBytes   int64     `json:"cipher_bytes"`
	ChunkCount    int       `json:"chunk_count"`
	ReceiptSHA256 string    `json:"receipt_sha256"`
	Acknowledged  bool      `json:"acknowledged"`
}

type RequestInfo struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxFiles  int       `json:"max_files"`
	MaxBytes  int64     `json:"max_bytes"`
	UsedFiles int       `json:"used_files"`
	UsedBytes int64     `json:"used_bytes"`
	PublicKey string    `json:"public_key"`
	Algorithm string    `json:"algorithm"`
}

type CollectResult struct {
	UploadID      string `json:"upload_id"`
	Path          string `json:"path"`
	PlainBytes    int64  `json:"plain_bytes"`
	PlainSHA256   string `json:"plain_sha256"`
	ReceiptSHA256 string `json:"receipt_sha256"`
}
