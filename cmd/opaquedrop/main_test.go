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
