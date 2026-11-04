// Package service is the transport-independent read layer behind the REST API
// and the MCP server. It returns plain structs and knows nothing about HTTP.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"perimeter/ent"
	"perimeter/ent/target"
	"perimeter/internal/storage"
)

// ErrNotFound is returned for a target that does not exist or is soft-deleted.
var ErrNotFound = errors.New("not found")

// InvalidError reports an argument the service cannot use. Field names the
// argument as the caller spells it (e.g. "ssl_grade").
type InvalidError struct {
	Field string
	Msg   string
}

func (e *InvalidError) Error() string { return e.Field + ": " + e.Msg }

// IsInvalid reports whether err is, or wraps, an *InvalidError.
func IsInvalid(err error) bool {
	var ie *InvalidError
	return errors.As(err, &ie)
}

func invalid(field, format string, args ...any) error {
	return &InvalidError{Field: field, Msg: fmt.Sprintf(format, args...)}
}

// Service answers read queries over targets, scans and changes, and makes the
// writes the API and MCP share with the UI.
type Service struct {
	st               storage.Storage
	client           *ent.Client
	certExpiryWindow time.Duration
	// rescanCooldown and sslScanning shape RequestRescan. SetRescanConfig sets
	// them to the server's values.
	rescanCooldown time.Duration
	sslScanning    bool
	// intervals judge staleness; SetScanIntervals sets them (#76).
	intervals ScanIntervals
}

// New builds a Service. certExpiryWindow is the horizon for "expiring soon",
// the same one the dashboard uses.
func New(st storage.Storage, client *ent.Client, certExpiryWindow time.Duration) *Service {
	return &Service{st: st, client: client, certExpiryWindow: certExpiryWindow}
}

// CertExpiryWindow is the horizon for "expiring soon", as configured.
func (s *Service) CertExpiryWindow() time.Duration {
	return s.certExpiryWindow
}

// ScanIntervals are the configured times between scans of each kind. A
// result is stale when its last check is more than StaleFactor intervals
// old: the scanner fell behind or the target wasn't scanned (issue #76).
type ScanIntervals struct {
	Ports, SSL, CSP time.Duration
}

// StaleFactor is how many intervals a result may be old before it's stale.
const StaleFactor = 2

// Stale reports whether a result last checked at lastSeen is stale for a
// scan kind with this interval. A zero interval or time is never stale.
func Stale(lastSeen time.Time, interval time.Duration, now time.Time) bool {
	return interval > 0 && !lastSeen.IsZero() && now.Sub(lastSeen) > StaleFactor*interval
}

// SetScanIntervals sets the scan intervals staleness is judged against.
func (s *Service) SetScanIntervals(iv ScanIntervals) { s.intervals = iv }

// SetRescanConfig sets how long a target waits between rescan requests and
// whether SSL Labs scanning runs. A rescan flags SSL only when it runs.
func (s *Service) SetRescanConfig(cooldown time.Duration, sslScanning bool) {
	s.rescanCooldown = cooldown
	s.sslScanning = sslScanning
}

// Page is one page of a list. NextOffset is nil on the last page.
type Page[T any] struct {
	Items      []T  `json:"items"`
	Total      int  `json:"total"`
	NextOffset *int `json:"next_offset,omitempty"`
}

// newPage wraps items, which start at offset in a list of total entries.
func newPage[T any](items []T, total, offset int) Page[T] {
	if items == nil {
		items = []T{}
	}
	p := Page[T]{Items: items, Total: total}
	if next := offset + len(items); next < total {
		p.NextOffset = &next
	}
	return p
}

// clampLimit applies the default for a missing limit and the cap for a large
// one.
func clampLimit(limit, def, most int) int {
	switch {
	case limit <= 0:
		return def
	case limit > most:
		return most
	}
	return limit
}

// Summary is the at-a-glance view: totals, the certificates that will expire
// soonest, and what changed in the last week.
type Summary struct {
	Totals SummaryTotals `json:"totals"`
	// SSLScanning is false when the server has SSL scanning off, and then the
	// SSL and certificate totals are always empty.
	SSLScanning   bool            `json:"ssl_scanning"`
	Expiring      []TargetSummary `json:"expiring"`
	RecentChanges []Change        `json:"recent_changes"`
}

// SummaryTotals are the counts behind the dashboard stat cards and badges.
type SummaryTotals struct {
	Targets        int            `json:"targets"`
	ByReachability map[string]int `json:"by_reachability"`
	OpenPorts      int            `json:"open_ports"`
	CSPIssues      int            `json:"csp_issues"`
	// ExpiringCerts are not yet expired and expire within the window.
	ExpiringCerts int `json:"expiring_certs"`
	ExpiredCerts  int `json:"expired_certs"`
	// WeakSSL are graded C or worse, including F, T and M.
	WeakSSL int `json:"weak_ssl"`
	// SSLUnscanned are the live targets with no SSL grade yet.
	SSLUnscanned int `json:"ssl_unscanned"`
	// Stale counts results last checked more than two intervals ago, so a
	// stalled scanner shows (issue #76).
	Stale StaleTotals `json:"stale"`
}

// StaleTotals count stale results by kind: targets for SSL and CSP, IPs for
// ports. SSL is 0 when SSL scanning is off.
type StaleTotals struct {
	SSL   int `json:"ssl"`
	CSP   int `json:"csp"`
	Ports int `json:"ports"`
}

const (
	expiringListSize   = 10
	recentChangesDays  = 7
	recentChangesLimit = 20
)

// Summary builds the overview as of now.
func (s *Service) Summary(ctx context.Context, now time.Time) (*Summary, error) {
	stats, err := s.st.TargetStats(ctx, storage.TargetFilter{}, now, s.certExpiryWindow)
	if err != nil {
		return nil, err
	}
	byState, err := s.st.StateCounts(ctx, storage.TargetFilter{})
	if err != nil {
		return nil, err
	}
	expired, err := s.client.Target.Query().
		Where(target.LatestCertExpiryNotNil(), target.LatestCertExpiryLT(now)).
		Count(ctx)
	if err != nil {
		return nil, err
	}
	weak, err := s.st.TargetStats(ctx, storage.TargetFilter{SSLBelow: "B"}, now, s.certExpiryWindow)
	if err != nil {
		return nil, err
	}
	// The default query hides soft-deleted targets, like the count above.
	unscanned, err := s.client.Target.Query().
		Where(target.Or(target.LatestSslGradeIsNil(), target.LatestSslGrade(""))).
		Count(ctx)
	if err != nil {
		return nil, err
	}

	out := &Summary{
		SSLScanning: s.sslScanning,
		Totals: SummaryTotals{
			Targets:       stats.Total,
			OpenPorts:     stats.OpenPorts,
			CSPIssues:     stats.CSPIssues,
			ExpiringCerts: stats.ExpiringCerts,
			ExpiredCerts:  expired,
			WeakSSL:       weak.Total,
			SSLUnscanned:  unscanned,
		},
		Expiring:      []TargetSummary{},
		RecentChanges: []Change{},
	}
	var sslCutoff, cspCutoff, portCutoff time.Time
	if s.sslScanning && s.intervals.SSL > 0 {
		sslCutoff = now.Add(-StaleFactor * s.intervals.SSL)
	}
	if s.intervals.CSP > 0 {
		cspCutoff = now.Add(-StaleFactor * s.intervals.CSP)
	}
	if s.intervals.Ports > 0 {
		portCutoff = now.Add(-StaleFactor * s.intervals.Ports)
	}
	st := &out.Totals.Stale
	if st.SSL, st.CSP, st.Ports, err = s.st.StaleCounts(ctx, sslCutoff, cspCutoff, portCutoff); err != nil {
		return nil, err
	}

	out.Totals.ByReachability = make(map[string]int, len(byState))
	for state, n := range byState {
		out.Totals.ByReachability[string(state)] = n
	}

	if out.Expiring, err = s.expiringSoon(ctx, now, expired); err != nil {
		return nil, err
	}

	changes, err := s.allChangesSince(ctx, now.Add(-recentChangesDays*24*time.Hour))
	if err != nil {
		return nil, err
	}
	// Newest first, at most recentChangesLimit.
	for i := len(changes) - 1; i >= 0 && len(out.RecentChanges) < recentChangesLimit; i-- {
		out.RecentChanges = append(out.RecentChanges, changes[i])
	}
	return out, nil
}

// expiringSoon lists up to expiringListSize targets whose certificate expires
// within the window, soonest first. Already expired certificates are in that
// set and sort first, so the first expired entries are skipped by offset.
// The window is zero when the caller disabled it, and then nothing matches.
func (s *Service) expiringSoon(ctx context.Context, now time.Time, expired int) ([]TargetSummary, error) {
	if s.certExpiryWindow <= 0 {
		return nil, nil
	}
	rows, err := s.st.ListTargets(ctx,
		storage.TargetFilter{ExpiringWithin: s.certExpiryWindow},
		storage.TargetSort{Field: storage.SortExpiry},
		expiringListSize, expired)
	if err != nil {
		return nil, err
	}
	out := make([]TargetSummary, 0, len(rows))
	for _, t := range rows {
		out = append(out, toSummary(t, now))
	}
	return out, nil
}
