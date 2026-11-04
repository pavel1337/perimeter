package importer

import (
	"context"
	"fmt"
	"strings"
)

// Source defines the interface for an import source.
//
// Fetch returns the names it found. When some zones failed to load it returns
// the names from the others together with a *ZoneErrors, so the sync can
// import what it got but still count as failed (issue #71).
type Source interface {
	Name() string
	Fetch(ctx context.Context) ([]string, error)
}

// ZoneErrors lists the zones whose records failed to load during a Fetch.
type ZoneErrors struct {
	Zones []ZoneError
}

// ZoneError is one zone that failed to load.
type ZoneError struct {
	Zone string
	Err  error
}

func (e *ZoneErrors) Error() string {
	parts := make([]string, len(e.Zones))
	for i, z := range e.Zones {
		parts[i] = fmt.Sprintf("zone %s: %v", z.Zone, z.Err)
	}
	return strings.Join(parts, "; ")
}

// add records a failed zone.
func (e *ZoneErrors) add(zone string, err error) {
	e.Zones = append(e.Zones, ZoneError{Zone: zone, Err: err})
}

// orNil is e as an error, or nil when no zone failed.
func (e *ZoneErrors) orNil() error {
	if len(e.Zones) == 0 {
		return nil
	}
	return e
}
