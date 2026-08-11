package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CAOShurong/opaquedrop/internal/collector"
)

func TestServeRejectsInvalidTrustedProxyBeforeStartup(t *testing.T) {
	err := run([]string{"serve", "--trusted-proxy", "not-a-cidr"})
	if err == nil || !strings.Contains(err.Error(), "invalid trusted proxy") {
		t.Fatalf("serve error = %v", err)
	}
}

func TestCollectRejectsInvalidUploadIDBeforeReadingKey(t *testing.T) {
	err := run([]string{"collect", "--key", "missing.json", "--upload", "../unsafe"})
	if err == nil || !strings.Contains(err.Error(), "invalid upload ID") {
		t.Fatalf("collect error = %v", err)
	}
}

func TestCollectRejectsInvalidReadRetriesBeforeReadingKey(t *testing.T) {
	err := run([]string{"collect", "--key", "missing.json", "--read-retries", "-1"})
	if err == nil || !strings.Contains(err.Error(), "--read-retries") {
		t.Fatalf("collect error = %v", err)
	}
}

func TestCollectRejectsAllWithoutListBeforeReadingKey(t *testing.T) {
	err := run([]string{"collect", "--key", "missing.json", "--all"})
	if err == nil || !strings.Contains(err.Error(), "--all requires --list") {
		t.Fatalf("collect error = %v", err)
	}
}

func TestWriteInspectionsEscapesNamesAndShowsState(t *testing.T) {
	completed := time.Date(2026, time.August, 11, 12, 34, 56, 0, time.UTC)
	var output bytes.Buffer
	if err := writeInspections(&output, []collector.Inspection{{
		UploadID: "QQQQQQQQQQQQQQQQQQQQQQ", Name: "line\nbreak\x1b.txt", PlainBytes: 42,
		CompletedAt: completed, Acknowledged: true, MetadataVerified: true,
	}}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if strings.Contains(got, "line\nbreak") || strings.Contains(got, "\x1b") {
		t.Fatalf("inspection name was written as terminal control data: %q", got)
	}
	for _, want := range []string{"QQQQQQQQQQQQQQQQQQQQQQ", "acknowledged", "2026-08-11T12:34:56Z", "42", `"line\nbreak\x1b.txt"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("inspection output %q does not contain %q", got, want)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("output closed") }

func TestWriteInspectionsReturnsOutputFailure(t *testing.T) {
	err := writeInspections(failingWriter{}, []collector.Inspection{{
		UploadID: "QQQQQQQQQQQQQQQQQQQQQQ", Name: "file.txt", MetadataVerified: true,
	}})
	if err == nil || !strings.Contains(err.Error(), "output closed") {
		t.Fatalf("writeInspections error = %v", err)
	}
}
