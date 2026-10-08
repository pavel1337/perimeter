package storage

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"entgo.io/ent/dialect/sql"

	"perimeter/ent"
	"perimeter/ent/cspscan"
	"perimeter/ent/ip"
	"perimeter/ent/port"
	"perimeter/ent/portscan"
	"perimeter/ent/predicate"
	"perimeter/ent/sslscan"
	"perimeter/ent/tag"
	"perimeter/ent/target"
)

// TargetFilter narrows the dashboard's target list (issue #17). Zero values
// mean "no constraint"; set fields combine with AND. Every filter runs in
// SQL against the summary columns (issue #14), except Port, which joins
// through ips -> port_scans -> ports.
type TargetFilter struct {
	// States keeps targets in any of these reachability states.
	States []target.Reachability
	// Tag keeps targets carrying the tag with this name.
	Tag string
	// CSP is one of "", "issues" (latest_csp_finding_count > 0), "ok"
	// (= 0), or "none" (NULL: never probed, or no HTTP response).
	CSP string
	// SSLGrade keeps targets whose latest_ssl_grade equals it exactly.
	SSLGrade string
	// SSLBelow keeps graded targets ranked strictly worse than this grade:
	// 0 < latest_ssl_grade_rank < gradeRanks[SSLBelow]. Ungraded targets
	// (rank 0) never match, since "no grade" is not "a bad grade".
	SSLBelow string
	// Port keeps targets where some IP's newest port scan has this port
	// open. 0 means no constraint.
	Port int
	// ExpiringWithin keeps targets whose latest_cert_expiry is before
	// now+ExpiringWithin, including certificates that already expired.
	// 0 means no constraint.
	ExpiringWithin time.Duration
}

// Sort fields accepted by TargetSort.Field.
const (
	SortTarget = "target" // input, alphabetical
	SortCSP    = "csp"    // latest_csp_finding_count
	SortPorts  = "ports"  // open_port_count
	SortSSL    = "ssl"    // grade: ascending is best first (A+, A, ... F)
	SortExpiry = "expiry" // latest_cert_expiry: ascending is soonest first
)

// SortFields lists the valid TargetSort.Field values.
var SortFields = []string{SortTarget, SortCSP, SortPorts, SortSSL, SortExpiry}

// TargetSort orders the target list (issue #16). The zero value sorts by
// target name ascending.
//
// Rows with nothing to say for the sorted column (NULL CSP count or expiry,
// ungraded SSL rank 0) always sort last, in both directions, so flipping
// the sort never fills the top of the page with them. Ties break on input,
// then id, so pagination is stable.
type TargetSort struct {
	Field string
	Desc  bool
}

// TargetStats are the dashboard stat cards, aggregated over every target
// matching a filter, not just the current page (issue #21).
type TargetStats struct {
	Total int
	// OpenPorts sums open_port_count.
	OpenPorts int
	// ExpiringCerts counts certificates expiring after now but within the
	// window. Already expired certificates do not count.
	ExpiringCerts int
	// CSPIssues counts targets with latest_csp_finding_count > 0.
	CSPIssues int
}

// ErrInvalidGrade is returned for an SSLBelow grade not in gradeRanks.
var ErrInvalidGrade = errors.New("invalid SSL grade")

// ErrInvalidCSPFilter is returned for a TargetFilter.CSP value that is not
// one of "", "issues", "ok" or "none".
var ErrInvalidCSPFilter = errors.New("invalid CSP filter")

// ErrInvalidSort is returned for a TargetSort.Field not in SortFields.
var ErrInvalidSort = errors.New("invalid sort field")

// targetPredicates turns f into SQL predicates. ListTargets and TargetStats
// both use it, so the page and the stat cards always agree on the matches.
func targetPredicates(f TargetFilter) ([]predicate.Target, error) {
	var ps []predicate.Target
	if len(f.States) > 0 {
		ps = append(ps, target.ReachabilityIn(f.States...))
	}
	if f.Tag != "" {
		ps = append(ps, target.HasTagsWith(tag.Name(f.Tag)))
	}
	switch f.CSP {
	case "":
	case "issues":
		ps = append(ps, target.LatestCspFindingCountGT(0))
	case "ok":
		ps = append(ps, target.LatestCspFindingCountEQ(0))
	case "none":
		ps = append(ps, target.LatestCspFindingCountIsNil())
	default:
		return nil, fmt.Errorf("%w: %q", ErrInvalidCSPFilter, f.CSP)
	}
	if f.SSLGrade != "" {
		ps = append(ps, target.LatestSslGrade(f.SSLGrade))
	}
	if f.SSLBelow != "" {
		if !IsGrade(f.SSLBelow) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidGrade, f.SSLBelow)
		}
		ps = append(ps,
			target.LatestSslGradeRankGT(0),
			target.LatestSslGradeRankLT(gradeRanks[f.SSLBelow]),
		)
	}
	if f.Port != 0 {
		// The newest scan of each IP only: an older scan that had the port
		// open must not count once a newer scan has closed it.
		newest := predicate.PortScan(latestPerParent(portscan.Table, portscan.IPColumn))
		ps = append(ps, target.HasIpsWith(ip.HasScansWith(
			newest,
			portscan.HasPortsWith(port.Number(f.Port)),
		)))
	}
	if f.ExpiringWithin != 0 {
		ps = append(ps,
			target.LatestCertExpiryNotNil(),
			target.LatestCertExpiryLT(time.Now().Add(f.ExpiringWithin)),
		)
	}
	return ps, nil
}

// targetOrder turns sort into ORDER BY terms, always ending with input and
// id ascending so pages are stable.
func targetOrder(sort TargetSort) ([]target.OrderOption, error) {
	dir := sql.OrderAsc()
	if sort.Desc {
		dir = sql.OrderDesc()
	}
	var terms []target.OrderOption
	switch sort.Field {
	case "", SortTarget:
		terms = append(terms, target.ByInput(dir))
	case SortCSP:
		terms = append(terms, target.ByLatestCspFindingCount(sql.OrderNullsLast(), dir))
	case SortPorts:
		terms = append(terms, target.ByOpenPortCount(dir))
	case SortSSL:
		// Ungraded (rank 0) last in both directions. Ascending is best
		// first, which is rank descending.
		terms = append(terms, func(s *sql.Selector) {
			s.OrderExpr(sql.ExprP(s.C(target.FieldLatestSslGradeRank) + " = 0"))
		})
		rankDir := sql.OrderDesc()
		if sort.Desc {
			rankDir = sql.OrderAsc()
		}
		terms = append(terms, target.ByLatestSslGradeRank(rankDir))
	case SortExpiry:
		terms = append(terms, target.ByLatestCertExpiry(sql.OrderNullsLast(), dir))
	default:
		return nil, fmt.Errorf("%w: %q", ErrInvalidSort, sort.Field)
	}
	return append(terms, target.ByInput(sql.OrderAsc()), target.ByID(sql.OrderAsc())), nil
}

// withTargetDetails eager-loads what the dashboard shows, exactly as
// GetTargets does: each IP's newest port scan with its ports, the newest SSL
// and CSP scan, and tags.
func withTargetDetails(q *ent.TargetQuery) *ent.TargetQuery {
	return q.
		WithIps(func(q *ent.IPQuery) {
			q.WithScans(func(sq *ent.PortScanQuery) {
				sq.Where(latestPerParent(portscan.Table, portscan.IPColumn)).
					WithPorts()
			})
		}).
		WithSslScans(func(q *ent.SSLScanQuery) {
			q.Where(latestPerParent(sslscan.Table, sslscan.TargetColumn))
		}).
		WithCspScans(func(q *ent.CSPScanQuery) {
			q.Where(latestPerParent(cspscan.Table, cspscan.TargetColumn))
		}).
		WithTags()
}

// ListTargets returns one page of targets matching f, ordered by s, loaded
// like GetTargets (IPs with their newest port scan and ports, newest SSL and
// CSP scan, tags). limit <= 0 means no limit.
func (s *EntStorage) ListTargets(ctx context.Context, f TargetFilter, sort TargetSort, limit, offset int) ([]*ent.Target, error) {
	preds, err := targetPredicates(f)
	if err != nil {
		return nil, err
	}
	order, err := targetOrder(sort)
	if err != nil {
		return nil, err
	}
	q := s.client.Target.Query().Where(preds...).Order(order...)
	if limit > 0 {
		q.Limit(limit)
	}
	if offset > 0 {
		q.Offset(offset)
	}
	return withTargetDetails(q).All(ctx)
}

// TargetStats aggregates the stat cards over every target matching f.
// ExpiringCerts uses now and window; the ExpiringWithin filter in f uses the
// wall clock, as it does for ListTargets.
func (s *EntStorage) TargetStats(ctx context.Context, f TargetFilter, now time.Time, window time.Duration) (TargetStats, error) {
	preds, err := targetPredicates(f)
	if err != nil {
		return TargetStats{}, err
	}
	matching := func(extra ...predicate.Target) *ent.TargetQuery {
		return s.client.Target.Query().Where(slices.Concat(preds, extra)...)
	}

	var st TargetStats
	if st.Total, err = matching().Count(ctx); err != nil {
		return TargetStats{}, err
	}
	// SUM over no rows is NULL, so an empty match set is all zeros.
	if st.Total == 0 {
		return st, nil
	}
	if st.OpenPorts, err = matching().Aggregate(ent.Sum(target.FieldOpenPortCount)).Int(ctx); err != nil {
		return TargetStats{}, err
	}
	if st.ExpiringCerts, err = matching(
		target.LatestCertExpiryGT(now),
		target.LatestCertExpiryLT(now.Add(window)),
	).Count(ctx); err != nil {
		return TargetStats{}, err
	}
	if st.CSPIssues, err = matching(target.LatestCspFindingCountGT(0)).Count(ctx); err != nil {
		return TargetStats{}, err
	}
	return st, nil
}

// IsGrade reports whether g is an SSL Labs grade with a rank, i.e. a valid
// TargetFilter.SSLBelow value.
func IsGrade(g string) bool {
	_, ok := gradeRanks[g]
	return ok
}
