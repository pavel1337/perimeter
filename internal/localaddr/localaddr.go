// Package localaddr tells whether an IP address belongs to this machine.
//
// When Perimeter scans the public IP of the host it runs on, the connections
// never leave the machine, so the provider's firewall is skipped: ports that
// are filtered from outside show as open (issue #79). Results for such an
// address are marked "this host: not seen from outside".
package localaddr

import (
	"net"
	"sync"
	"time"
)

// refreshEvery is how long the interface addresses are cached; addresses
// change rarely, and this is asked on every target page.
const refreshEvery = time.Minute

var (
	mu      sync.Mutex
	cached  map[string]bool
	fetched time.Time

	// interfaceAddrs lists this machine's addresses; a variable for tests.
	interfaceAddrs = net.InterfaceAddrs
)

// IsLocal reports whether ip is assigned to one of this machine's network
// interfaces. Loopback addresses count too.
func IsLocal(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() {
		return true
	}
	mu.Lock()
	defer mu.Unlock()
	if cached == nil || time.Since(fetched) > refreshEvery {
		cached = map[string]bool{}
		if addrs, err := interfaceAddrs(); err == nil {
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok {
					cached[n.IP.String()] = true
				}
			}
		}
		fetched = time.Now()
	}
	return cached[parsed.String()]
}
