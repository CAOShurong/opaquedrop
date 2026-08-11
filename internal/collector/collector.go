package collector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CAOShurong/opaquedrop/internal/core"
	"github.com/CAOShurong/opaquedrop/internal/cryptobox"
	"github.com/CAOShurong/opaquedrop/internal/model"
)

type Client struct {
	Key  model.KeyFile
	HTTP *http.Client
}

func New(key model.KeyFile) *Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
	return &Client{Key: key, HTTP: &http.Client{Transport: transport}}
}

func (c *Client) List(ctx context.Context) ([]model.Receipt, error) {
	var response struct {
		Uploads []model.Receipt `json:"uploads"`
	}
	if err := c.jsonRequest(ctx, http.MethodGet, c.endpoint("/api/v1/collect/%s/uploads", c.Key.RequestID), nil, &response); err != nil {
		return nil, err
	}
	return response.Uploads, nil
}

func (c *Client) CollectAll(ctx context.Context, outDir string, acknowledge bool) ([]model.CollectResult, error) {
	receipts, err := c.List(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]model.CollectResult, 0)
	for _, receipt := range receipts {
		if receipt.Acknowledged {
			continue
		}
		result, err := c.CollectOne(ctx, receipt, outDir, acknowledge)
		if err != nil {
			return results, fmt.Errorf("collect upload %s: %w", receipt.UploadID, err)
		}
		results = append(results, result)
	}
	return results, nil
}

func (c *Client) CollectOne(ctx context.Context, receipt model.Receipt, outDir string, acknowledge bool) (model.CollectResult, error) {
	if receipt.RequestID != c.Key.RequestID || !core.ValidID(receipt.UploadID) {
		return model.CollectResult{}, errors.New("receipt does not match key file")
	}
	manifestURL := c.endpoint("/api/v1/collect/%s/uploads/%s/manifest", c.Key.RequestID, receipt.UploadID)
	manifestRaw, err := c.bytesRequest(ctx, manifestURL, 64<<10)
	if err != nil {
		return model.CollectResult{}, err
	}
	var manifest model.Manifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return model.CollectResult{}, errors.New("server returned an invalid manifest")
	}
	if manifest.RequestID != c.Key.RequestID || manifest.UploadID != receipt.UploadID || manifest.ChunkCount != receipt.ChunkCount || manifest.PlainSize != receipt.PlainSize {
		return model.CollectResult{}, errors.New("manifest and receipt disagree")
	}
	opener, err := cryptobox.NewOpener(c.Key, manifest)
	if err != nil {
		return model.CollectResult{}, err
	}
	metadata, err := opener.Metadata(manifest.EncryptedMetadata)
	if err != nil {
		return model.CollectResult{}, err
	}
	if err := prepareOutputDir(outDir); err != nil {
		return model.CollectResult{}, err
	}
	temp, err := os.CreateTemp(outDir, ".opaquedrop-*.part")
	if err != nil {
		return model.CollectResult{}, err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	_ = temp.Chmod(0o600)
	plainHash := sha256.New()
	chunkDigests := make([][]byte, manifest.ChunkCount)
	var written int64
	for i := 0; i < manifest.ChunkCount; i++ {
		chunkURL := c.endpoint("/api/v1/collect/%s/uploads/%s/chunks/%d", c.Key.RequestID, receipt.UploadID, i)
		ciphertext, err := c.bytesRequest(ctx, chunkURL, manifest.ChunkSize+17)
		if err != nil {
			temp.Close()
			return model.CollectResult{}, err
		}
		digest := sha256.Sum256(ciphertext)
		chunkDigests[i] = append([]byte(nil), digest[:]...)
		plain, err := opener.Chunk(i, ciphertext)
		if err != nil {
			temp.Close()
			return model.CollectResult{}, err
		}
		remaining := manifest.PlainSize - written
		if int64(len(plain)) > remaining || (i < manifest.ChunkCount-1 && int64(len(plain)) != manifest.ChunkSize) {
			temp.Close()
			return model.CollectResult{}, errors.New("decrypted chunk size does not match manifest")
		}
		if _, err := temp.Write(plain); err != nil {
			temp.Close()
			return model.CollectResult{}, err
		}
		_, _ = plainHash.Write(plain)
		written += int64(len(plain))
	}
	if written != manifest.PlainSize {
		temp.Close()
		return model.CollectResult{}, errors.New("decrypted file size does not match manifest")
	}
	computedReceipt := cryptobox.ReceiptRoot(manifestRaw, chunkDigests)
	if !strings.EqualFold(computedReceipt, receipt.ReceiptSHA256) {
		temp.Close()
		return model.CollectResult{}, errors.New("receipt hash does not match stored ciphertext")
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return model.CollectResult{}, err
	}
	if err := temp.Close(); err != nil {
		return model.CollectResult{}, err
	}
	destination := uniqueDestination(outDir, core.SafeFilename(metadata.Name))
	if err := os.Rename(tempPath, destination); err != nil {
		return model.CollectResult{}, err
	}
	if acknowledge {
		ackURL := c.endpoint("/api/v1/collect/%s/uploads/%s/ack", c.Key.RequestID, receipt.UploadID)
		if err := c.jsonRequest(ctx, http.MethodPost, ackURL, bytes.NewReader([]byte("{}")), nil); err != nil {
			return model.CollectResult{}, fmt.Errorf("file saved but acknowledgement failed: %w", err)
		}
	}
	return model.CollectResult{
		UploadID: receipt.UploadID, Path: destination, PlainBytes: written,
		PlainSHA256: hex.EncodeToString(plainHash.Sum(nil)), ReceiptSHA256: computedReceipt,
	}, nil
}

func (c *Client) bytesRequest(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "OpaqueDrop "+c.Key.CollectToken)
	response, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, responseError(response)
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("server response exceeds protocol limit")
	}
	return b, nil
}

func (c *Client) jsonRequest(ctx context.Context, method, url string, body io.Reader, target any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "OpaqueDrop "+c.Key.CollectToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError(response)
	}
	if target == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target)
}

func responseError(response *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &payload) == nil && payload.Error.Code != "" {
		return fmt.Errorf("server returned %d %s: %s", response.StatusCode, payload.Error.Code, payload.Error.Message)
	}
	return fmt.Errorf("server returned HTTP %d", response.StatusCode)
}

func (c *Client) endpoint(format string, args ...any) string {
	return strings.TrimRight(c.Key.ServerURL, "/") + fmt.Sprintf(format, args...)
}

func prepareOutputDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output path must be a real directory, not a symlink")
	}
	_ = os.Chmod(path, 0o700)
	return nil
}

func uniqueDestination(dir, name string) string {
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	candidate := filepath.Join(dir, name)
	for i := 2; ; i++ {
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		}
		candidate = filepath.Join(dir, fmt.Sprintf("%s-%d%s", base, i, ext))
	}
}
