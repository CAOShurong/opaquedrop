package collector

import (
	"encoding/json"
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
