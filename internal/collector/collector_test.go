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
			destination, err := publishOutput(temp.Name(), dir, "same.txt")
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
	if _, err := publishOutput(temp.Name(), dir, strings.Repeat("x", 300)); err == nil {
		t.Fatal("overlong component did not return an error")
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
