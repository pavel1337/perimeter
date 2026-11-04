package localaddr

import (
	"net"
	"testing"
)

func TestIsLocal(t *testing.T) {
	old := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = old; cached = nil })
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("203.0.113.5"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}
	cached = nil
	for ip, want := range map[string]bool{
		"203.0.113.5":  true,
		"2001:db8::1":  true,
		"2001:DB8::1":  true, // normalized
		"127.0.0.1":    true,
		"::1":          true,
		"203.0.113.6":  false, // same subnet, another machine
		"198.51.100.1": false,
		"not an ip":    false,
	} {
		if got := IsLocal(ip); got != want {
			t.Errorf("IsLocal(%q) = %v, want %v", ip, got, want)
		}
	}
}
