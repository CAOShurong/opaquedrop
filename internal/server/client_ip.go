package server

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type clientIPResolver struct {
	trusted []netip.Prefix
}

func newClientIPResolver(trusted []netip.Prefix) clientIPResolver {
	return clientIPResolver{trusted: append([]netip.Prefix(nil), trusted...)}
}

func ParseTrustedProxies(values []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			addr, addrErr := netip.ParseAddr(value)
			if addrErr != nil {
				return nil, fmt.Errorf("invalid trusted proxy %q: use an IP address or CIDR", value)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}

func (r clientIPResolver) resolve(request *http.Request) string {
	peer, ok := parsePeer(request.RemoteAddr)
	if !ok {
		return request.RemoteAddr
	}
	peer = peer.WithZone("")
	if !r.isTrusted(peer) {
		return peer.String()
	}

	forwarded := strings.Join(request.Header.Values("X-Forwarded-For"), ",")
	if forwarded == "" {
		return peer.String()
	}
	parts := strings.Split(forwarded, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		addr, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil {
			return peer.String()
		}
		addr = addr.WithZone("")
		if !r.isTrusted(addr) {
			return addr.String()
		}
	}
	return peer.String()
}

func (r clientIPResolver) isTrusted(addr netip.Addr) bool {
	for _, prefix := range r.trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func parsePeer(remote string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		addr, parseErr := netip.ParseAddr(host)
		return addr, parseErr == nil
	}
	addr, err := netip.ParseAddr(strings.Trim(remote, "[]"))
	return addr, err == nil
}
