package cryptobox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CAOShurong/opaquedrop/internal/model"
)

const metadataNonceIndex = ^uint32(0)

type Opener struct {
	gcm         cipher.AEAD
	noncePrefix []byte
	requestID   string
	uploadID    string
	headerHash  string
}

func NewOpener(key model.KeyFile, manifest model.Manifest) (*Opener, error) {
	if manifest.Version != model.ProtocolVersion || manifest.Algorithm != model.Algorithm {
		return nil, errors.New("unsupported encryption protocol")
	}
	if manifest.RequestID != key.RequestID {
		return nil, errors.New("key file does not match request")
	}
	headerHash := HeaderSHA256(manifest)
	want, err := hex.DecodeString(manifest.HeaderSHA256)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("invalid manifest header binding")
	}
	got, _ := hex.DecodeString(headerHash)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return nil, errors.New("manifest header binding mismatch")
	}
	privateBytes, err := base64.RawURLEncoding.DecodeString(key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	privateKey, err := ecdh.P256().NewPrivateKey(privateBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	publicBytes, err := base64.RawURLEncoding.DecodeString(manifest.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode ephemeral public key: %w", err)
	}
	publicKey, err := ecdh.P256().NewPublicKey(publicBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}
	shared, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}
	salt, err := base64.RawURLEncoding.DecodeString(manifest.Salt)
	if err != nil || len(salt) != 32 {
		return nil, errors.New("invalid HKDF salt")
	}
	info := KDFInfo(manifest.RequestID, manifest.UploadID)
	aesKey, err := hkdf.Key(sha256.New, shared, salt, info, 32)
	if err != nil {
		return nil, fmt.Errorf("derive AES key: %w", err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	prefix, err := base64.RawURLEncoding.DecodeString(manifest.NoncePrefix)
	if err != nil || len(prefix) != 8 {
		return nil, errors.New("invalid nonce prefix")
	}
	return &Opener{gcm: gcm, noncePrefix: prefix, requestID: manifest.RequestID, uploadID: manifest.UploadID, headerHash: headerHash}, nil
}

func (o *Opener) Metadata(ciphertext string) (model.FileMetadata, error) {
	b, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return model.FileMetadata{}, errors.New("invalid encrypted metadata encoding")
	}
	plain, err := o.gcm.Open(nil, o.nonce(metadataNonceIndex), b, []byte(MetadataAAD(o.requestID, o.uploadID, o.headerHash)))
	if err != nil {
		return model.FileMetadata{}, errors.New("metadata authentication failed")
	}
	var metadata model.FileMetadata
	if err := json.Unmarshal(plain, &metadata); err != nil {
		return model.FileMetadata{}, errors.New("decrypted metadata is invalid")
	}
	return metadata, nil
}

func (o *Opener) Chunk(index int, ciphertext []byte) ([]byte, error) {
	if index < 0 || uint64(index) >= uint64(metadataNonceIndex) {
		return nil, errors.New("chunk index out of range")
	}
	plain, err := o.gcm.Open(nil, o.nonce(uint32(index)), ciphertext, []byte(ChunkAAD(o.requestID, o.uploadID, o.headerHash, index)))
	if err != nil {
		return nil, fmt.Errorf("chunk %d authentication failed", index)
	}
	return plain, nil
}

func (o *Opener) nonce(index uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, o.noncePrefix)
	binary.BigEndian.PutUint32(nonce[8:], index)
	return nonce
}

func KDFInfo(requestID, uploadID string) string {
	return "OpaqueDrop/v1/request/" + requestID + "/upload/" + uploadID
}

func MetadataAAD(requestID, uploadID, headerHash string) string {
	return "opaquedrop/v1|" + requestID + "|" + uploadID + "|header|" + headerHash + "|metadata"
}

func ChunkAAD(requestID, uploadID, headerHash string, index int) string {
	return fmt.Sprintf("opaquedrop/v1|%s|%s|header|%s|chunk|%d", requestID, uploadID, headerHash, index)
}

func HeaderCanonical(m model.Manifest) string {
	return fmt.Sprintf("opaquedrop/v1/header\nversion=%d\nrequest_id=%s\nupload_id=%s\nalgorithm=%s\nephemeral_public_key=%s\nsalt=%s\nnonce_prefix=%s\nchunk_size=%d\nchunk_count=%d\nplain_size=%d\n",
		m.Version, m.RequestID, m.UploadID, m.Algorithm, m.EphemeralPublicKey, m.Salt, m.NoncePrefix, m.ChunkSize, m.ChunkCount, m.PlainSize)
}

func HeaderSHA256(m model.Manifest) string {
	sum := sha256.Sum256([]byte(HeaderCanonical(m)))
	return hex.EncodeToString(sum[:])
}

func ReceiptRoot(manifest []byte, chunkDigests [][]byte) string {
	h := sha256.New()
	h.Write([]byte("OpaqueDrop receipt v1\x00"))
	manifestHash := sha256.Sum256(manifest)
	h.Write(manifestHash[:])
	for _, digest := range chunkDigests {
		h.Write(digest)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
