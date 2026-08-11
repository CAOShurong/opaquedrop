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

type CollectOptions struct {
	Acknowledge bool
	UploadIDs   []string
	FailFast    bool
}

const (
	maxJSONResponse   = 1 << 20
	maxListResponse   = 8 << 20
	maxNameCollisions = 10_000
)

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
	if err := c.jsonRequestLimit(ctx, http.MethodGet, c.endpoint("/api/v1/collect/%s/uploads", c.Key.RequestID), nil, &response, maxListResponse); err != nil {
		return nil, err
	}
	return response.Uploads, nil
}

func (c *Client) CollectAll(ctx context.Context, outDir string, acknowledge bool) ([]model.CollectResult, error) {
	return c.Collect(ctx, outDir, CollectOptions{Acknowledge: acknowledge})
}

func (c *Client) Collect(ctx context.Context, outDir string, options CollectOptions) ([]model.CollectResult, error) {
	receipts, err := c.List(ctx)
	if err != nil {
		return nil, err
	}
	receipts, selectionErrors := selectReceipts(receipts, options.UploadIDs)
	results := make([]model.CollectResult, 0)
	failures := append([]error(nil), selectionErrors...)
	if options.FailFast && len(failures) > 0 {
		return results, errors.Join(failures...)
	}
	for _, receipt := range receipts {
		result, err := c.CollectOne(ctx, receipt, outDir, options.Acknowledge)
		if result.Path != "" {
			results = append(results, result)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("collect upload %s: %w", receipt.UploadID, err))
			var outputErr *outputError
			if options.FailFast || errors.As(err, &outputErr) || ctx.Err() != nil {
				return results, errors.Join(failures...)
			}
		}
	}
	return results, errors.Join(failures...)
}

type outputError struct {
	Err error
}

func (e *outputError) Error() string { return e.Err.Error() }
func (e *outputError) Unwrap() error { return e.Err }

func selectReceipts(receipts []model.Receipt, uploadIDs []string) ([]model.Receipt, []error) {
	if len(uploadIDs) == 0 {
		selected := make([]model.Receipt, 0, len(receipts))
		for _, receipt := range receipts {
			if !receipt.Acknowledged {
				selected = append(selected, receipt)
			}
		}
		return selected, nil
	}

	byID := make(map[string]model.Receipt, len(receipts))
	for _, receipt := range receipts {
		byID[receipt.UploadID] = receipt
	}
	selected := make([]model.Receipt, 0, len(uploadIDs))
	failures := make([]error, 0)
	seen := make(map[string]struct{}, len(uploadIDs))
	for _, uploadID := range uploadIDs {
		if _, duplicate := seen[uploadID]; duplicate {
			continue
		}
		seen[uploadID] = struct{}{}
		if !core.ValidID(uploadID) {
			failures = append(failures, fmt.Errorf("invalid upload ID %q", uploadID))
			continue
		}
		receipt, ok := byID[uploadID]
		if !ok {
			failures = append(failures, fmt.Errorf("upload %s is not a completed submission", uploadID))
			continue
		}
		selected = append(selected, receipt)
	}
	return selected, failures
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
		return model.CollectResult{}, &outputError{Err: err}
	}
	temp, err := os.CreateTemp(outDir, ".opaquedrop-*.part")
	if err != nil {
		return model.CollectResult{}, &outputError{Err: err}
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
		if err := ctx.Err(); err != nil {
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
			return model.CollectResult{}, &outputError{Err: err}
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
	if err := ctx.Err(); err != nil {
		temp.Close()
		return model.CollectResult{}, err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return model.CollectResult{}, &outputError{Err: err}
	}
	if err := temp.Close(); err != nil {
		return model.CollectResult{}, &outputError{Err: err}
	}
	if err := ctx.Err(); err != nil {
		return model.CollectResult{}, err
	}
	destination, err := publishOutput(tempPath, outDir, core.SafeFilename(metadata.Name))
	if err != nil {
		return model.CollectResult{}, &outputError{Err: err}
	}
	result := model.CollectResult{
		UploadID: receipt.UploadID, Path: destination, PlainBytes: written,
		PlainSHA256: hex.EncodeToString(plainHash.Sum(nil)), ReceiptSHA256: computedReceipt,
	}
	if acknowledge {
		ackURL := c.endpoint("/api/v1/collect/%s/uploads/%s/ack", c.Key.RequestID, receipt.UploadID)
		if err := c.jsonRequest(ctx, http.MethodPost, ackURL, bytes.NewReader([]byte("{}")), nil); err != nil {
			return result, fmt.Errorf("file saved but acknowledgement failed: %w", err)
		}
	}
	return result, nil
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
	return c.jsonRequestLimit(ctx, method, url, body, target, maxJSONResponse)
}

func (c *Client) jsonRequestLimit(ctx context.Context, method, url string, body io.Reader, target any, limit int64) error {
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
	payload, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(payload)) > limit {
		return errors.New("server response exceeds protocol limit")
	}
	return json.Unmarshal(payload, target)
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

func publishOutput(tempPath, dir, name string) (string, error) {
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for attempt := 1; attempt <= maxNameCollisions; attempt++ {
		candidateName := name
		if attempt > 1 {
			candidateName = fmt.Sprintf("%s-%d%s", base, attempt, ext)
		}
		candidate := filepath.Join(dir, candidateName)
		if err := os.Link(tempPath, candidate); err == nil {
			_ = os.Remove(tempPath)
			return candidate, nil
		} else if errors.Is(err, os.ErrExist) {
			continue
		} else {
			return "", err
		}
	}
	return "", fmt.Errorf("refusing more than %d filename collision attempts", maxNameCollisions)
}
