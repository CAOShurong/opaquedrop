package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CAOShurong/opaquedrop/internal/model"
)

func TestPublishOutputNeverReplacesACollision(t *testing.T) {
	dir := t.TempDir()
	const count = 8
	paths := make(chan string, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			temp, err := os.CreateTemp(dir, ".verified-*.part")
			if err != nil {
				errs <- err
				return
			}
			if _, err = fmt.Fprintf(temp, "payload-%d", i); err == nil {
				err = temp.Close()
			}
			if err != nil {
				errs <- err
				return
			}
			destination, err := publishOutput(temp.Name(), dir, "same.txt", os.Link)
			if err != nil {
				errs <- err
				return
			}
			paths <- destination
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	close(paths)
	seen := make(map[string]struct{}, count)
	for path := range paths {
		if _, duplicate := seen[path]; duplicate {
			t.Fatalf("destination reused: %s", path)
		}
		seen[path] = struct{}{}
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != count {
		t.Fatalf("published %d files, want %d", len(seen), count)
	}
}

func TestCloseRequestDoesNotReplayAcrossRedirect(t *testing.T) {
	targetRequests := 0
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		targetRequests++
		response.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	sourceRequests := 0
	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		sourceRequests++
		response.Header().Set("Location", target.URL)
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	client := New(model.KeyFile{RequestID: "RRRRRRRRRRRRRRRRRRRRRR", ServerURL: source.URL, CollectToken: "collect-token"})
	client.HTTP = source.Client()
	_, err := client.CloseRequest(t.Context())
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("CloseRequest error = %v", err)
	}
	if sourceRequests != 1 || targetRequests != 0 {
		t.Fatalf("close request replayed: source=%d target=%d", sourceRequests, targetRequests)
	}
}

func TestReadRetriesTruncatedBodyAndTransientStatus(t *testing.T) {
	t.Run("truncated body", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			attempts++
			if attempts == 1 {
				response.Header().Set("Content-Length", "12")
				_, _ = response.Write([]byte("short"))
				return
			}
			_, _ = response.Write([]byte("complete"))
		}))
		defer server.Close()
		const capability = "CAPABILITY-DO-NOT-LOG"
		client := New(model.KeyFile{ServerURL: server.URL, CollectToken: capability})
		client.HTTP = server.Client()
		client.ReadRetries = 1
		client.retryBaseDelay = 0
		var retryLog bytes.Buffer
		client.RetryLog = &retryLog
		got, err := client.bytesRequest(t.Context(), server.URL, 64)
		if err != nil || string(got) != "complete" || attempts != 2 {
			t.Fatalf("bytesRequest() = %q, %v after %d attempts", got, err, attempts)
		}
		if !strings.Contains(retryLog.String(), "read attempt 1/2 failed") {
			t.Fatalf("retry was not reported: %q", retryLog.String())
		}
		if strings.Contains(retryLog.String(), capability) {
			t.Fatalf("retry log contained collect capability: %q", retryLog.String())
		}
	})

	t.Run("temporary status and Retry-After", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			attempts++
			response.Header().Set("Retry-After", "7")
			http.Error(response, "temporarily unavailable", http.StatusServiceUnavailable)
		}))
		defer server.Close()
		client := New(model.KeyFile{ServerURL: server.URL, CollectToken: "test"})
		client.HTTP = server.Client()
		client.ReadRetries = 1
		client.retryMaxDelay = 10 * time.Second
		var delays []time.Duration
		client.sleep = func(ctx context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		}
		_, err := client.bytesRequest(t.Context(), server.URL, 64)
		if err == nil || attempts != 2 || len(delays) != 1 || delays[0] != 7*time.Second {
			t.Fatalf("temporary response attempts=%d delays=%v error=%v", attempts, delays, err)
		}
	})
}

func TestReadRetryBoundaries(t *testing.T) {
	t.Run("disabled retry makes one attempt", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			attempts++
			http.Error(response, "temporary", http.StatusBadGateway)
		}))
		defer server.Close()
		client := New(model.KeyFile{ServerURL: server.URL, CollectToken: "test"})
		client.HTTP = server.Client()
		client.ReadRetries = 0
		_, err := client.bytesRequest(t.Context(), server.URL, 64)
		if err == nil || attempts != 1 {
			t.Fatalf("disabled retry attempts=%d error=%v", attempts, err)
		}
	})

	t.Run("permanent status is not retried", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			attempts++
			http.Error(response, "not found", http.StatusNotFound)
		}))
		defer server.Close()
		client := New(model.KeyFile{ServerURL: server.URL, CollectToken: "test"})
		client.HTTP = server.Client()
		client.ReadRetries = 3
		_, err := client.bytesRequest(t.Context(), server.URL, 64)
		if err == nil || attempts != 1 {
			t.Fatalf("permanent response attempts=%d error=%v", attempts, err)
		}
	})

	t.Run("excessive Retry-After is not retried early", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			attempts++
			response.Header().Set("Retry-After", "31")
			http.Error(response, "slow down", http.StatusTooManyRequests)
		}))
		defer server.Close()
		client := New(model.KeyFile{ServerURL: server.URL, CollectToken: "test"})
		client.HTTP = server.Client()
		client.ReadRetries = 3
		client.retryMaxDelay = 30 * time.Second
		_, err := client.bytesRequest(t.Context(), server.URL, 64)
		if err == nil || attempts != 1 || !strings.Contains(err.Error(), "Retry-After") {
			t.Fatalf("long Retry-After attempts=%d error=%v", attempts, err)
		}
	})

	t.Run("maximum Retry-After is accepted", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			attempts++
			response.Header().Set("Retry-After", "30")
			http.Error(response, "temporary", http.StatusServiceUnavailable)
		}))
		defer server.Close()
		client := New(model.KeyFile{ServerURL: server.URL, CollectToken: "test"})
		client.HTTP = server.Client()
		client.ReadRetries = 1
		client.retryMaxDelay = 30 * time.Second
		var delays []time.Duration
		client.sleep = func(ctx context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		}
		_, err := client.bytesRequest(t.Context(), server.URL, 64)
		if err == nil || attempts != 2 || len(delays) != 1 || delays[0] != 30*time.Second {
			t.Fatalf("maximum Retry-After attempts=%d delays=%v error=%v", attempts, delays, err)
		}
	})

	t.Run("cancellation interrupts backoff", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			attempts++
			http.Error(response, "temporary", http.StatusBadGateway)
		}))
		defer server.Close()
		client := New(model.KeyFile{ServerURL: server.URL, CollectToken: "test"})
		client.HTTP = server.Client()
		client.ReadRetries = 3
		enteredSleep := make(chan struct{})
		client.sleep = func(ctx context.Context, delay time.Duration) error {
			close(enteredSleep)
			<-ctx.Done()
			return ctx.Err()
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			_, err := client.bytesRequest(ctx, server.URL, 64)
			done <- err
		}()
		<-enteredSleep
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) || attempts != 1 {
			t.Fatalf("canceled retry attempts=%d error=%v", attempts, err)
		}
	})
}

func TestWaitForReceiptsPollsUntilPendingSubmission(t *testing.T) {
	const requestID = "RRRRRRRRRRRRRRRRRRRRRR"
	const uploadID = "UUUUUUUUUUUUUUUUUUUUUU"
	listRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		listRequests++
		uploads := []model.Receipt{}
		if listRequests >= 3 {
			uploads = append(uploads, model.Receipt{RequestID: requestID, UploadID: uploadID})
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"uploads": uploads})
	}))
	defer server.Close()

	client := New(model.KeyFile{RequestID: requestID, ServerURL: server.URL, CollectToken: "collect-token"})
	client.HTTP = server.Client()
	now := time.Date(2026, time.August, 12, 1, 2, 3, 0, time.UTC)
	client.now = func() time.Time { return now }
	var delays []time.Duration
	client.sleep = func(ctx context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		now = now.Add(delay)
		return nil
	}

	receipts, err := client.WaitForReceipts(t.Context(), WaitOptions{
		Timeout: 10 * time.Second, PollInterval: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if listRequests != 3 || len(receipts) != 1 || receipts[0].UploadID != uploadID {
		t.Fatalf("requests=%d receipts=%+v", listRequests, receipts)
	}
	if fmt.Sprint(delays) != "[2s 2s]" {
		t.Fatalf("poll delays = %v", delays)
	}
}

func TestWaitForReceiptsRequiresAllExplicitUploadIDs(t *testing.T) {
	const requestID = "RRRRRRRRRRRRRRRRRRRRRR"
	const firstID = "AAAAAAAAAAAAAAAAAAAAAA"
	const secondID = "BBBBBBBBBBBBBBBBBBBBBB"
	listRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		listRequests++
		uploads := []model.Receipt{{RequestID: requestID, UploadID: firstID, Acknowledged: true}}
		if listRequests >= 2 {
			uploads = append(uploads, model.Receipt{RequestID: requestID, UploadID: secondID})
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"uploads": uploads})
	}))
	defer server.Close()

	client := New(model.KeyFile{RequestID: requestID, ServerURL: server.URL, CollectToken: "collect-token"})
	client.HTTP = server.Client()
	client.now = time.Now
	client.sleep = func(context.Context, time.Duration) error { return nil }
	receipts, err := client.WaitForReceipts(t.Context(), WaitOptions{
		Timeout: time.Minute, PollInterval: time.Second, UploadIDs: []string{firstID, secondID, firstID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if listRequests != 2 || len(receipts) != 2 {
		t.Fatalf("requests=%d receipts=%+v", listRequests, receipts)
	}
}

func TestWaitForReceiptsUsesBoundedFinalDelay(t *testing.T) {
	listRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		listRequests++
		_, _ = response.Write([]byte(`{"uploads":[]}`))
	}))
	defer server.Close()

	client := New(model.KeyFile{RequestID: "RRRRRRRRRRRRRRRRRRRRRR", ServerURL: server.URL, CollectToken: "collect-token"})
	client.HTTP = server.Client()
	now := time.Date(2026, time.August, 12, 1, 2, 3, 0, time.UTC)
	client.now = func() time.Time { return now }
	var delays []time.Duration
	client.sleep = func(ctx context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		now = now.Add(delay)
		return nil
	}

	_, err := client.WaitForReceipts(t.Context(), WaitOptions{
		Timeout: 5 * time.Second, PollInterval: 2 * time.Second,
	})
	if !errors.Is(err, ErrWaitTimeout) {
		t.Fatalf("WaitForReceipts error = %v", err)
	}
	if listRequests != 4 || fmt.Sprint(delays) != "[2s 2s 1s]" {
		t.Fatalf("requests=%d delays=%v", listRequests, delays)
	}
}

func TestWaitForReceiptsPropagatesCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write([]byte(`{"uploads":[]}`))
	}))
	defer server.Close()
	client := New(model.KeyFile{RequestID: "RRRRRRRRRRRRRRRRRRRRRR", ServerURL: server.URL, CollectToken: "collect-token"})
	client.HTTP = server.Client()
	client.sleep = func(context.Context, time.Duration) error { return context.Canceled }
	_, err := client.WaitForReceipts(t.Context(), WaitOptions{
		Timeout: time.Minute, PollInterval: time.Second,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitForReceipts error = %v", err)
	}
}

func TestWaitForReceiptsBoundsAnInFlightListRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer server.Close()
	client := New(model.KeyFile{RequestID: "RRRRRRRRRRRRRRRRRRRRRR", ServerURL: server.URL, CollectToken: "collect-token"})
	client.HTTP = server.Client()
	started := time.Now()
	_, err := client.WaitForReceipts(t.Context(), WaitOptions{
		Timeout: 100 * time.Millisecond, PollInterval: time.Second,
	})
	if !errors.Is(err, ErrWaitTimeout) {
		t.Fatalf("WaitForReceipts error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("in-flight list exceeded wait deadline: %s", elapsed)
	}
}

func TestCollectWaitsBeforeSelectingReceipts(t *testing.T) {
	const requestID = "RRRRRRRRRRRRRRRRRRRRRR"
	const uploadID = "UUUUUUUUUUUUUUUUUUUUUU"
	listRequests := 0
	manifestRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/uploads"):
			listRequests++
			uploads := []model.Receipt{}
			if listRequests >= 2 {
				uploads = append(uploads, model.Receipt{RequestID: requestID, UploadID: uploadID})
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"uploads": uploads})
		case strings.HasSuffix(request.URL.Path, "/manifest"):
			manifestRequests++
			http.Error(response, "fixture manifest failure", http.StatusNotFound)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	client := New(model.KeyFile{RequestID: requestID, ServerURL: server.URL, CollectToken: "collect-token"})
	client.HTTP = server.Client()
	client.ReadRetries = 0
	client.sleep = func(context.Context, time.Duration) error { return nil }
	_, err := client.Collect(t.Context(), t.TempDir(), CollectOptions{
		WaitTimeout: time.Minute, PollInterval: time.Second,
	})
	if err == nil || errors.Is(err, ErrWaitTimeout) {
		t.Fatalf("Collect error = %v", err)
	}
	if listRequests != 2 || manifestRequests != 1 {
		t.Fatalf("list requests=%d manifest requests=%d", listRequests, manifestRequests)
	}
}

func TestInvalidListJSONIsNotRetried(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		attempts++
		_, _ = response.Write([]byte(`{"uploads":`))
	}))
	defer server.Close()
	client := New(model.KeyFile{RequestID: "RRRRRRRRRRRRRRRRRRRRRR", ServerURL: server.URL, CollectToken: "test"})
	client.HTTP = server.Client()
	client.ReadRetries = 3
	if _, err := client.List(t.Context()); err == nil || attempts != 1 {
		t.Fatalf("invalid JSON attempts=%d error=%v", attempts, err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, time.August, 11, 8, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		value string
		want  time.Duration
		ok    bool
	}{
		{value: "7", want: 7 * time.Second, ok: true},
		{value: now.Add(9 * time.Second).Format(http.TimeFormat), want: 9 * time.Second, ok: true},
		{value: now.Add(-time.Minute).Format(http.TimeFormat), want: 0, ok: true},
		{value: "18446744074", want: time.Duration(1<<63 - 1), ok: true},
		{value: "9223372036854775807", want: time.Duration(1<<63 - 1), ok: true},
		{value: "999999999999999999999999999999", want: time.Duration(1<<63 - 1), ok: true},
		{value: "invalid", want: 0, ok: false},
	} {
		got, ok := parseRetryAfter(test.value, now)
		if got != test.want || ok != test.ok {
			t.Errorf("parseRetryAfter(%q) = %s, %t; want %s, %t", test.value, got, ok, test.want, test.ok)
		}
	}
}

func TestPublishOutputReturnsComponentErrors(t *testing.T) {
	dir := t.TempDir()
	temp, err := os.CreateTemp(dir, ".verified-*.part")
	if err != nil {
		t.Fatal(err)
	}
	if err := temp.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := publishOutput(temp.Name(), dir, strings.Repeat("x", 300), os.Link); err == nil {
		t.Fatal("overlong component did not return an error")
	}
}

func TestOutputPublicationPreflightCleansProbeFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "received")
	if err := prepareOutputDir(dir, os.Link); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("preflight left files: %v", entries)
	}
}

func TestOutputPublicationPreflightRejectsCopyMasqueradingAsLink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "received")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	err := preflightOutputPublication(dir, func(oldname, newname string) error {
		contents, err := os.ReadFile(oldname)
		if err != nil {
			return err
		}
		return os.WriteFile(newname, contents, 0o600)
	})
	if err == nil || !strings.Contains(err.Error(), "did not preserve hard-link identity") {
		t.Fatalf("preflight error = %v", err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("identity failure left probe files: %v", entries)
	}
}

func TestOutputPublicationPreflightStopsBeforeChunkDownload(t *testing.T) {
	vectorBytes, err := os.ReadFile(filepath.Join("..", "..", "testdata", "protocol-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RecipientPrivateKey string `json:"recipient_private_key"`
		RecipientPublicKey  string `json:"recipient_public_key"`
		ManifestJSON        string `json:"manifest_json"`
		ReceiptSHA256       string `json:"receipt_sha256"`
	}
	if err := json.Unmarshal(vectorBytes, &vector); err != nil {
		t.Fatal(err)
	}
	const requestID = "AQEBAQEBAQEBAQEBAQEBAQ"
	const uploadID = "AgICAgICAgICAgICAgICAg"
	chunkRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/api/v1/collect/"+requestID+"/uploads":
			_ = json.NewEncoder(response).Encode(map[string]any{"uploads": []model.Receipt{{
				Version: 1, RequestID: requestID, UploadID: uploadID, CompletedAt: time.Now().UTC(),
				PlainSize: 56, CipherBytes: 88, ChunkCount: 2, ReceiptSHA256: vector.ReceiptSHA256,
			}}})
		case strings.HasSuffix(request.URL.Path, "/manifest"):
			_, _ = response.Write([]byte(vector.ManifestJSON))
		case strings.Contains(request.URL.Path, "/chunks/"):
			chunkRequests++
			http.Error(response, "chunk must not be requested", http.StatusInternalServerError)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client := New(model.KeyFile{
		SchemaVersion: model.SchemaVersion, RequestID: requestID, ServerURL: server.URL,
		CollectToken: "collect-token", PrivateKey: vector.RecipientPrivateKey, PublicKey: vector.RecipientPublicKey,
	})
	client.HTTP = server.Client()
	client.ReadRetries = 0
	client.link = func(string, string) error { return errors.New("operation not supported") }
	outDir := filepath.Join(t.TempDir(), "received")
	_, err = client.Collect(t.Context(), outDir, CollectOptions{})
	if err == nil || !strings.Contains(err.Error(), "atomic no-replace hard-link publish") {
		t.Fatalf("Collect error = %v", err)
	}
	if chunkRequests != 0 {
		t.Fatalf("collector fetched %d chunks before detecting unsupported output", chunkRequests)
	}
	entries, readErr := os.ReadDir(outDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("failed preflight left output files: %v", entries)
	}
}

func TestListAcceptsMaximumRequestReceiptSet(t *testing.T) {
	uploads := make([]model.Receipt, 10_000)
	for i := range uploads {
		uploads[i] = model.Receipt{
			Version: 1, RequestID: "RRRRRRRRRRRRRRRRRRRRRR", UploadID: "UUUUUUUUUUUUUUUUUUUUUU",
			CompletedAt: time.Unix(int64(i), 0).UTC(), PlainSize: 1, CipherBytes: 17, ChunkCount: 1,
			ReceiptSHA256: strings.Repeat("a", 64),
		}
	}
	payload, err := json.Marshal(map[string]any{"uploads": uploads})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) <= 1<<20 {
		t.Fatalf("fixture does not cross legacy response bound: %d", len(payload))
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(payload)
	}))
	defer server.Close()
	client := New(model.KeyFile{RequestID: "RRRRRRRRRRRRRRRRRRRRRR", ServerURL: server.URL, CollectToken: "test"})
	client.HTTP = server.Client()
	got, err := client.List(t.Context())
	if err != nil || len(got) != len(uploads) {
		t.Fatalf("List() = %d receipts, %v; want %d", len(got), err, len(uploads))
	}
	if len(payload) > maxListResponse {
		t.Fatalf("maximum legal receipt set exceeds configured bound: %d > %d", len(payload), maxListResponse)
	}
}
