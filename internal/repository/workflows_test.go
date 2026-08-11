package repository

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var actionUse = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*([^\s#]+)`)

func TestThirdPartyActionsArePinnedToCommits(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.yml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("workflow discovery = %v, %v", paths, err)
	}
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range actionUse.FindAllStringSubmatch(string(body), -1) {
			use := strings.Trim(match[1], `"'`)
			if strings.HasPrefix(use, "./") {
				continue
			}
			parts := strings.Split(use, "@")
			if len(parts) != 2 || len(parts[1]) != 40 {
				t.Errorf("%s uses mutable action reference %q", path, use)
				continue
			}
			if _, err := hex.DecodeString(parts[1]); err != nil {
				t.Errorf("%s uses non-commit action reference %q", path, use)
			}
		}
	}
}

func TestReleaseWaitsForFullGatesAndAttestsArchives(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, required := range []string{
		"needs: [ci, codeql]",
		"git rev-parse origin/main",
		"actions/attest-build-provenance@",
		"sha256sum --check SHA256SUMS",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("release workflow is missing %q", required)
		}
	}
}
