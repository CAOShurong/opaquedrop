package main

import (
	"strings"
	"testing"
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
