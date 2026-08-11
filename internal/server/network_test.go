package server

import (
	"fmt"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestClientIPResolverTrustBoundary(t *testing.T) {
	tests := []struct {
		name    string
		remote  string
		forward string
		trusted []netip.Prefix
		want    string
	}{
		{
			name:   "direct client cannot spoof forwarding header",
			remote: "192.0.2.44:1234", forward: "198.51.100.8",
			trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, want: "192.0.2.44",
		},
		{
			name:   "trusted loopback proxy identifies client",
			remote: "127.0.0.1:1234", forward: "198.51.100.8",
			trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, want: "198.51.100.8",
		},
		{
			name:   "trusted proxy chain is walked right to left",
			remote: "127.0.0.1:1234", forward: "203.0.113.9, 10.2.3.4",
			trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8")}, want: "203.0.113.9",
		},
		{
			name:   "malformed rightmost hop fails closed to peer",
			remote: "127.0.0.1:1234", forward: "203.0.113.9, not-an-ip",
			trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, want: "127.0.0.1",
		},
		{
			name:   "proxy-appended client wins before attacker-controlled garbage",
			remote: "127.0.0.1:1234", forward: "not-an-ip, 198.51.100.8",
			trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, want: "198.51.100.8",
		},
		{
			name:   "IPv6 proxy and client are supported",
			remote: "[::1]:1234", forward: "2001:db8::44",
			trusted: []netip.Prefix{netip.MustParsePrefix("::1/128")}, want: "2001:db8::44",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://example.test/", nil)
			r.RemoteAddr = test.remote
			r.Header.Set("X-Forwarded-For", test.forward)
			if got := newClientIPResolver(test.trusted).resolve(r); got != test.want {
				t.Fatalf("client IP = %q, want %q", got, test.want)
			}
		})
	}
}

func TestFailureLimiterHasConstantBucketBound(t *testing.T) {
	limiter := newFailureLimiter()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }

	for i := 0; i < maxFailureBuckets+200; i++ {
		limiter.failure(fmt.Sprintf("198.51.%d.%d", i/256, i%256))
	}
	if got := len(limiter.windows); got > maxFailureBuckets {
		t.Fatalf("failure limiter retained %d buckets, maximum is %d", got, maxFailureBuckets)
	}
	if !limiter.blocked(overflowFailureBucket) {
		t.Fatal("overflow bucket did not rate-limit excess distinct peers")
	}

	now = now.Add(failureWindowDuration)
	limiter.failure("203.0.113.1")
	if got := len(limiter.windows); got != 1 {
		t.Fatalf("expired buckets were not reclaimed: got %d", got)
	}
}
