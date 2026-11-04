package importer

import (
	"log"
	"strings"
)

// scannableName reports whether a DNS record name, relative to its zone,
// names a host that can be scanned (issue #72). The importers keep A, AAAA
// and CNAME records, but these get through and can never resolve to a host:
//   - a label starting with "_": DKIM keys (selector1._domainkey),
//     certificate validation records (_3f9c….www), SRV-style names
//   - a wildcard ("*", "*.apps"): hosts under it are not listed anywhere, so
//     they have to be added by hand. The skip is logged so that's visible.
func scannableName(name, zone string) bool {
	for _, label := range strings.Split(name, ".") {
		if strings.HasPrefix(label, "_") {
			return false
		}
		if label == "*" {
			log.Printf("Importer: skipping wildcard %s.%s; hosts under it must be added by hand", name, zone)
			return false
		}
	}
	return true
}
