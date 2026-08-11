package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRequestBundleContainsNoRawCapabilitiesOrPrivateKey(t *testing.T) {
	now := time.Now().UTC()
	bundle, key, err := MakeRequest("https://drop.example", "Tax documents", now, now.Add(time.Hour), 3, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(bundle)
	serialized := string(b)
	if strings.Contains(serialized, key.CollectToken) || strings.Contains(serialized, key.PrivateKey) || strings.Contains(serialized, key.SubmitURL) {
		t.Fatal("server bundle contains recipient secret material")
	}
	if !strings.Contains(key.SubmitURL, "#t=") || strings.Contains(strings.Split(key.SubmitURL, "#")[0], key.CollectToken) {
		t.Fatalf("submit capability is not confined to URL fragment: %s", key.SubmitURL)
	}
}

func TestPublicRequestsRequireHTTPSOutsideLocalhost(t *testing.T) {
	now := time.Now().UTC()
	if _, _, err := MakeRequest("http://drop.example", "Files", now, now.Add(time.Hour), 1, 1, false); err == nil {
		t.Fatal("non-local HTTP URL accepted")
	}
	if _, _, err := MakeRequest("http://127.0.0.1:8080", "Files", now, now.Add(time.Hour), 1, 1, false); err != nil {
		t.Fatalf("localhost HTTP rejected: %v", err)
	}
}

func TestSafeFilenameConfinesPathsAndDeviceCharacters(t *testing.T) {
	cases := map[string]string{
		"../../secret.txt":   "secret.txt",
		`..\\..\\secret.txt`: "secret.txt",
		"CON:<bad>?.txt":     "CON__bad__.txt",
		"  .  ":              "received-file",
	}
	for input, want := range cases {
		if got := SafeFilename(input); got != want {
			t.Errorf("SafeFilename(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseBytes(t *testing.T) {
	for input, want := range map[string]int64{"1B": 1, "2 KiB": 2048, "3MB": 3_000_000, "4GiB": 4 << 30} {
		got, err := ParseBytes(input)
		if err != nil || got != want {
			t.Errorf("ParseBytes(%q) = %d, %v; want %d", input, got, err, want)
		}
	}
	if _, err := ParseBytes("-1GiB"); err == nil {
		t.Fatal("negative size accepted")
	}
}
