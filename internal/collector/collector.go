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
	"strconv"
	"strings"
	"time"

	"github.com/CAOShurong/opaquedrop/internal/core"
	"github.com/CAOShurong/opaquedrop/internal/cryptobox"
	"github.com/CAOShurong/opaquedrop/internal/model"
)

type Client struct {
	Key         model.KeyFile
	HTTP        *http.Client
	ReadRetries int
	RetryLog    io.Writer

	retryBaseDelay time.Duration
	retryMaxDelay  time.Duration
	sleep          func(context.Context, time.Duration) error
	now            func() time.Time
	link           func(string, string) error
}

type CollectOptions struct {
	Acknowledge bool
	UploadIDs   []string
	FailFast    bool
}

type InspectOptions struct {
	UploadIDs           []string
	IncludeAcknowledged bool
	FailFast            bool
}

type Inspection struct {
	UploadID         string
	Name             string
	PlainBytes       int64
	CompletedAt      time.Time
	Acknowledged     bool
	MetadataVerified bool
}

const (
	DefaultReadRetries = 3
	MaxReadRetries     = 10

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
	return &Client{
		Key: key, HTTP: &http.Client{Transport: transport}, ReadRetries: DefaultReadRetries,
		retryBaseDelay: 250 * time.Millisecond, retryMaxDelay: 30 * time.Second,
		sleep: sleepContext, now: time.Now, link: os.Link,
	}
}

func (c *Client) List(ctx context.Context) ([]model.Receipt, error) {
	var response struct {
		Uploads []model.Receipt `json:"uploads"`
	}
	payload, err := c.bytesRequest(ctx, c.endpoint("/api/v1/collect/%s/uploads", c.Key.RequestID), maxListResponse)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, err
	}
	return response.Uploads, nil
}

// CloseRequest irreversibly stops new submissions while leaving completed
// ciphertext available to the collect capability.
func (c *Client) CloseRequest(ctx context.Context) (model.RequestClosure, error) {
	var closure model.RequestClosure
	url := c.endpoint("/api/v1/collect/%s/close", c.Key.RequestID)
	if err := c.jsonRequest(ctx, http.MethodPost, url, nil, &closure); err != nil {
		return model.RequestClosure{}, err
	}
	if closure.SchemaVersion != model.SchemaVersion || closure.RequestID != c.Key.RequestID || closure.ClosedAt.IsZero() {
		return model.RequestClosure{}, errors.New("server returned an invalid request closure")
	}
	return closure, nil
}

func (c *Client) CollectAll(ctx context.Context, outDir string, acknowledge bool) ([]model.CollectResult, error) {
	return c.Collect(ctx, outDir, CollectOptions{Acknowledge: acknowledge})
}

func (c *Client) Inspect(ctx context.Context, options InspectOptions) ([]Inspection, error) {
	receipts, err := c.List(ctx)
	if err != nil {
		return nil, err
	}
	receipts, selectionErrors := selectInspectionReceipts(receipts, options)
	results := make([]Inspection, 0, len(receipts))
	failures := append([]error(nil), selectionErrors...)
	if options.FailFast && len(failures) > 0 {
		return results, errors.Join(failures...)
	}
	for _, receipt := range receipts {
		if receipt.RequestID != c.Key.RequestID || !core.ValidID(receipt.UploadID) {
			failures = append(failures, errors.New("inspect receipt does not match key file"))
			if options.FailFast {
				return results, errors.Join(failures...)
			}
			continue
		}
		result := Inspection{
			UploadID: receipt.UploadID, Name: "<unreadable>", PlainBytes: receipt.PlainSize,
			CompletedAt: receipt.CompletedAt, Acknowledged: receipt.Acknowledged,
		}
		_, _, metadata, _, err := c.manifestMetadata(ctx, receipt)
		if err != nil {
			if ctx.Err() != nil {
				failures = append(failures, ctx.Err())
				return results, errors.Join(failures...)
			}
			results = append(results, result)
			failures = append(failures, fmt.Errorf("inspect upload %s: %w", receipt.UploadID, err))
			if options.FailFast {
				return results, errors.Join(failures...)
			}
			continue
		}
		result.Name = core.SafeFilename(metadata.Name)
		result.MetadataVerified = true
		results = append(results, result)
	}
	return results, errors.Join(failures...)
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

func selectInspectionReceipts(receipts []model.Receipt, options InspectOptions) ([]model.Receipt, []error) {
	if len(options.UploadIDs) > 0 {
		return selectReceipts(receipts, options.UploadIDs)
	}
	if options.IncludeAcknowledged {
		return receipts, nil
	}
	selected := make([]model.Receipt, 0, len(receipts))
	for _, receipt := range receipts {
		if !receipt.Acknowledged {
			selected = append(selected, receipt)
		}
	}
	return selected, nil
}

func (c *Client) CollectOne(ctx context.Context, receipt model.Receipt, outDir string, acknowledge bool) (model.CollectResult, error) {
	manifest, manifestRaw, metadata, opener, err := c.manifestMetadata(ctx, receipt)
	if err != nil {
		return model.CollectResult{}, err
	}
	link := c.link
	if link == nil {
		link = os.Link
	}
	if err := prepareOutputDir(outDir, link); err != nil {
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
	destination, err := publishOutput(tempPath, outDir, core.SafeFilename(metadata.Name), link)
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

func (c *Client) manifestMetadata(ctx context.Context, receipt model.Receipt) (model.Manifest, []byte, model.FileMetadata, *cryptobox.Opener, error) {
	if receipt.RequestID != c.Key.RequestID || !core.ValidID(receipt.UploadID) {
		return model.Manifest{}, nil, model.FileMetadata{}, nil, errors.New("receipt does not match key file")
	}
	manifestURL := c.endpoint("/api/v1/collect/%s/uploads/%s/manifest", c.Key.RequestID, receipt.UploadID)
	manifestRaw, err := c.bytesRequest(ctx, manifestURL, 64<<10)
	if err != nil {
		return model.Manifest{}, nil, model.FileMetadata{}, nil, err
	}
	var manifest model.Manifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return model.Manifest{}, nil, model.FileMetadata{}, nil, errors.New("server returned an invalid manifest")
	}
	if manifest.RequestID != c.Key.RequestID || manifest.UploadID != receipt.UploadID || manifest.ChunkCount != receipt.ChunkCount || manifest.PlainSize != receipt.PlainSize {
		return model.Manifest{}, nil, model.FileMetadata{}, nil, errors.New("manifest and receipt disagree")
	}
	opener, err := cryptobox.NewOpener(c.Key, manifest)
	if err != nil {
		return model.Manifest{}, nil, model.FileMetadata{}, nil, err
	}
	metadata, err := opener.Metadata(manifest.EncryptedMetadata)
	if err != nil {
		return model.Manifest{}, nil, model.FileMetadata{}, nil, err
	}
	return manifest, manifestRaw, metadata, opener, nil
}

func (c *Client) bytesRequest(ctx context.Context, url string, limit int64) ([]byte, error) {
	retries := c.ReadRetries
	if retries < 0 {
		retries = 0
	}
	if retries > MaxReadRetries {
		retries = MaxReadRetries
	}
	attempts := retries + 1
	for attempt := 1; attempt <= attempts; attempt++ {
		payload, retryAfter, retryable, err := c.bytesRequestOnce(ctx, url, limit)
		if err == nil {
			return payload, nil
		}
		if !retryable || attempt == attempts || ctx.Err() != nil {
			return nil, err
		}
		maxDelay := c.retryMaxDelay
		if maxDelay <= 0 {
			maxDelay = 30 * time.Second
		}
		if retryAfter > maxDelay {
			return nil, fmt.Errorf("%w (Retry-After %s exceeds maximum automatic wait %s)", err, retryAfter, maxDelay)
		}
		delay := c.retryDelay(attempt)
		if retryAfter > delay {
			delay = retryAfter
		}
		if c.RetryLog != nil {
			fmt.Fprintf(c.RetryLog, "read attempt %d/%d failed: %v; retrying in %s\n", attempt, attempts, err, delay)
		}
		sleep := c.sleep
		if sleep == nil {
			sleep = sleepContext
		}
		if err := sleep(ctx, delay); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("read retry loop exhausted")
}

func (c *Client) bytesRequestOnce(ctx context.Context, url string, limit int64) ([]byte, time.Duration, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, false, err
	}
	req.Header.Set("Authorization", "OpaqueDrop "+c.Key.CollectToken)
	response, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, ctx.Err() == nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		retryAfter, _ := parseRetryAfter(response.Header.Get("Retry-After"), c.currentTime())
		return nil, retryAfter, retryableReadStatus(response.StatusCode), responseError(response)
	}
	if response.ContentLength > limit {
		return nil, 0, false, errors.New("server response exceeds protocol limit")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, 0, ctx.Err() == nil, err
	}
	if int64(len(payload)) > limit {
		return nil, 0, false, errors.New("server response exceeds protocol limit")
	}
	return payload, 0, false, nil
}

func (c *Client) retryDelay(failedAttempt int) time.Duration {
	delay := c.retryBaseDelay
	if delay < 0 {
		delay = 0
	}
	maxDelay := c.retryMaxDelay
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}
	for i := 1; i < failedAttempt; i++ {
		if delay >= maxDelay/2 {
			return maxDelay
		}
		delay *= 2
	}
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

func (c *Client) currentTime() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func retryableReadStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if decimalDigits(value) {
		seconds, err := strconv.ParseUint(value, 10, 64)
		if err != nil || seconds > uint64((time.Duration(1<<63-1))/time.Second) {
			return time.Duration(1<<63 - 1), true
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := when.Sub(now)
	if delay < 0 {
		delay = 0
	}
	return delay, true
}

func decimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	requestClient := *client
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := requestClient.Do(req)
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

func prepareOutputDir(path string, link func(string, string) error) error {
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
	return preflightOutputPublication(path, link)
}

func preflightOutputPublication(dir string, link func(string, string) error) (resultErr error) {
	if link == nil {
		link = os.Link
	}
	probe, err := os.CreateTemp(dir, ".opaquedrop-publish-probe-*.part")
	if err != nil {
		return err
	}
	probePath := probe.Name()
	linkPath := probePath + ".link"
	defer func() {
		if err := os.Remove(linkPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove output publication probe link: %w", err))
		}
		if err := os.Remove(probePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove output publication probe: %w", err))
		}
	}()
	_ = probe.Chmod(0o600)
	if _, err := probe.Write([]byte("OpaqueDrop output publication probe\n")); err != nil {
		_ = probe.Close()
		return err
	}
	if err := probe.Sync(); err != nil {
		_ = probe.Close()
		return err
	}
	if err := probe.Close(); err != nil {
		return err
	}
	if err := link(probePath, linkPath); err != nil {
		return fmt.Errorf("output filesystem does not support OpaqueDrop's required atomic no-replace hard-link publish: %w", err)
	}
	sourceInfo, err := os.Stat(probePath)
	if err != nil {
		return err
	}
	linkInfo, err := os.Stat(linkPath)
	if err != nil {
		return err
	}
	if !os.SameFile(sourceInfo, linkInfo) {
		return errors.New("output filesystem did not preserve hard-link identity for OpaqueDrop's atomic no-replace publish")
	}
	return nil
}

func publishOutput(tempPath, dir, name string, link func(string, string) error) (string, error) {
	if link == nil {
		link = os.Link
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for attempt := 1; attempt <= maxNameCollisions; attempt++ {
		candidateName := name
		if attempt > 1 {
			candidateName = fmt.Sprintf("%s-%d%s", base, attempt, ext)
		}
		candidate := filepath.Join(dir, candidateName)
		if err := link(tempPath, candidate); err == nil {
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
