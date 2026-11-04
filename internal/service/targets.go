package service

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"perimeter/ent"
	"perimeter/ent/schema"
	"perimeter/ent/tag"
	"perimeter/ent/target"
	"perimeter/internal/storage"
	"perimeter/scanner/csp"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

// reachabilityByName maps the state names callers use to the stored values.
var reachabilityByName = map[string]target.Reachability{
	string(target.ReachabilityOk):          target.ReachabilityOk,
	string(target.ReachabilityUnreachable): target.ReachabilityUnreachable,
	string(target.ReachabilityUnresolved):  target.ReachabilityUnresolved,
	string(target.ReachabilityPending):     target.ReachabilityPending,
}

// TargetQuery is the filter, sort and page of a target list. Zero values mean
// "no constraint"; set fields combine with AND. Deleted lists soft-deleted
// targets instead, and then only Search and the paging fields apply.
type TargetQuery struct {
	// Search keeps targets whose input contains it, ignoring case.
	Search string
	// Tag keeps targets carrying the tag with this name.
	Tag string
	// States are reachability names: ok, unreachable, unresolved, pending.
	States []string
	// SSLBelow keeps graded targets ranked strictly worse than this grade.
	SSLBelow string
	// SSLGrade keeps targets whose newest SSL grade is exactly this.
	SSLGrade string
	// CSP is "", "issues", "ok" or "none".
	CSP string
	// Port keeps targets where some IP has this port open. 0 means none.
	Port int
	// ExpiringWithinDays keeps targets whose certificate expires within this
	// many days, expired ones included. 0 means no constraint.
	ExpiringWithinDays int
	// Expired keeps targets whose certificate has already expired.
	Expired bool
	// CertTrust is "", "untrusted" (grade T or M) or "trusted".
	CertTrust string
	Deleted   bool
	// Sort is one of storage.SortFields; empty sorts by input.
	Sort string
	Desc bool
	// Limit defaults to 50 and is capped at 200.
	Limit  int
	Offset int
}

// TargetSummary is a target as the lists show it.
type TargetSummary struct {
	ID           int      `json:"id"`
	Input        string   `json:"input"`
	IsIP         bool     `json:"is_ip"`
	Reachability string   `json:"reachability"`
	Tags         []string `json:"tags"`
	SSLGrade     string   `json:"ssl_grade,omitempty"`
	// CertProblems says why the certificate isn't trusted, e.g.
	// ["self-signed"]: the reason behind a T or M grade (issue #73). A
	// self-signed or name-mismatch certificate has no cert_expiry.
	CertProblems []string   `json:"cert_problems,omitempty"`
	CertExpiry   *time.Time `json:"cert_expiry,omitempty"`
	CertDaysLeft *int       `json:"cert_days_left,omitempty"`
	CSPFindings  *int       `json:"csp_findings,omitempty"`
	OpenPorts    int        `json:"open_ports"`
	CreatedAt    time.Time  `json:"created_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
}

// TargetDetail is one target with its newest scan of each kind.
type TargetDetail struct {
	TargetSummary
	ResolveError string     `json:"resolve_error,omitempty"`
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
	IPs          []IPDetail `json:"ips"`
	SSL          *SSLDetail `json:"ssl,omitempty"`
	CSP          *CSPDetail `json:"csp,omitempty"`
}

// IPDetail is one address of a target and its newest port scan.
type IPDetail struct {
	Address     string     `json:"address"`
	OpenPorts   []int      `json:"open_ports,omitempty"`
	LastChecked *time.Time `json:"last_checked,omitempty"`
	Error       string     `json:"error,omitempty"`
	// Stale is set when the last check is over two port intervals old (#76).
	Stale bool `json:"stale,omitempty"`
}

// SSLDetail is the newest SSL result of a target. When the newest check
// failed, LastCheckError says why and the result fields are the last real
// result (empty if there is none yet).
type SSLDetail struct {
	Grade           string     `json:"grade"`
	Status          string     `json:"status"`
	CertSubject     string     `json:"cert_subject,omitempty"`
	CertIssuer      string     `json:"cert_issuer,omitempty"`
	CertExpiry      *time.Time `json:"cert_expiry,omitempty"`
	Protocols       []string   `json:"protocols,omitempty"`
	Vulnerabilities []string   `json:"vulnerabilities,omitempty"`
	// CertProblems says why the certificate isn't trusted (#73).
	CertProblems []string  `json:"cert_problems,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastChecked  time.Time `json:"last_checked"`
	// Set when the newest check failed.
	LastCheckError    string     `json:"last_check_error,omitempty"`
	LastCheckFailedAt *time.Time `json:"last_check_failed_at,omitempty"`
	// Stale is set when the last check is over two SSL intervals old (#76).
	Stale bool `json:"stale,omitempty"`
}

// CSPFinding is a csp.Finding with the level its severity maps to, which the
// numeric severity alone does not convey.
type CSPFinding struct {
	csp.Finding
	Level string `json:"level"`
}

// CSPDetail is the newest CSP evaluation of a target.
type CSPDetail struct {
	Header     string       `json:"header,omitempty"`
	Findings   []CSPFinding `json:"findings,omitempty"`
	ProbeError string       `json:"probe_error,omitempty"`
	// The HTTP status and final URL of the response (#67). CSP is judged on
	// 2xx only; for 4xx and 5xx there are no findings.
	StatusCode int    `json:"status_code,omitempty"`
	FinalURL   string `json:"final_url,omitempty"`
	// Why the certificate failed verification; the response was read
	// without verifying it (#68). A final_url with the http scheme means the
	// result came over plain HTTP: nothing answered TLS on port 443.
	TLSProblem string `json:"tls_problem,omitempty"`
	// The other site the target redirects to; not judged (#70).
	RedirectHost string    `json:"redirect_host,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastChecked  time.Time `json:"last_checked"`
	// Stale is set when the last check is over two CSP intervals old (#76).
	Stale bool `json:"stale,omitempty"`
}

// HistoryEntry is one SSL, CSP or port scan row in a target's history.
// Summary reads as a change where the kind has one ("grade A → B").
type HistoryEntry struct {
	Kind        string    `json:"kind"`
	FirstSeen   time.Time `json:"first_seen"`
	LastChecked time.Time `json:"last_checked"`
	IP          string    `json:"ip,omitempty"`
	Summary     string    `json:"summary"`
	Grade       string    `json:"grade,omitempty"`
	Ports       []int     `json:"ports,omitempty"`
	// FindingsCount is set for CSP rows that got a response.
	FindingsCount *int   `json:"findings_count,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Tag is a label with the number of live targets carrying it.
type Tag struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	TargetCount int    `json:"target_count"`
}

// filter validates q and turns it into the storage filter.
func (q TargetQuery) filter() (storage.TargetFilter, error) {
	f := storage.TargetFilter{
		Search:    q.Search,
		Tag:       q.Tag,
		CSP:       q.CSP,
		SSLGrade:  q.SSLGrade,
		SSLBelow:  q.SSLBelow,
		Port:      q.Port,
		Expired:   q.Expired,
		CertTrust: q.CertTrust,
	}
	for _, name := range q.States {
		st, ok := reachabilityByName[name]
		if !ok {
			return f, invalid("state", "unknown state %q", name)
		}
		f.States = append(f.States, st)
	}
	switch q.CSP {
	case "", "issues", "ok", "none":
	default:
		return f, invalid("csp", "must be issues, ok or none, not %q", q.CSP)
	}
	if q.SSLGrade != "" && !storage.IsGrade(q.SSLGrade) {
		return f, invalid("ssl_grade", "unknown grade %q", q.SSLGrade)
	}
	if q.SSLBelow != "" && !storage.IsGrade(q.SSLBelow) {
		return f, invalid("ssl_below", "unknown grade %q; valid grades: A+, A, A-, B, C, D, E, F, T, M", q.SSLBelow)
	}
	if q.Port < 0 || q.Port > 65535 {
		return f, invalid("port", "must be between 1 and 65535")
	}
	if q.ExpiringWithinDays < 0 {
		return f, invalid("expiring_within_days", "must not be negative")
	}
	f.ExpiringWithin = time.Duration(q.ExpiringWithinDays) * 24 * time.Hour
	return f, nil
}

// sortBy validates the sort field and returns the storage sort.
func (q TargetQuery) sortBy() (storage.TargetSort, error) {
	field := q.Sort
	if field == "" {
		field = storage.SortTarget
	}
	if !slices.Contains(storage.SortFields, field) {
		return storage.TargetSort{}, invalid("sort", "unknown sort field %q", q.Sort)
	}
	return storage.TargetSort{Field: field, Desc: q.Desc}, nil
}

// ListTargets returns one page of targets matching q.
func (s *Service) ListTargets(ctx context.Context, q TargetQuery) (Page[TargetSummary], error) {
	if q.Offset < 0 {
		return Page[TargetSummary]{}, invalid("offset", "must not be negative")
	}
	limit := clampLimit(q.Limit, defaultLimit, maxLimit)
	if q.Deleted {
		return s.listDeleted(ctx, q, limit)
	}
	f, err := q.filter()
	if err != nil {
		return Page[TargetSummary]{}, err
	}
	sort, err := q.sortBy()
	if err != nil {
		return Page[TargetSummary]{}, err
	}

	now := time.Now()
	stats, err := s.st.TargetStats(ctx, f, now, s.certExpiryWindow)
	if err != nil {
		return Page[TargetSummary]{}, err
	}
	rows, err := s.st.ListTargets(ctx, f, sort, limit, q.Offset)
	if err != nil {
		return Page[TargetSummary]{}, err
	}
	items := make([]TargetSummary, 0, len(rows))
	for _, t := range rows {
		items = append(items, toSummary(t, now))
	}
	return newPage(items, stats.Total, q.Offset), nil
}

// listDeleted pages through the soft-deleted targets, most recently deleted
// first. Only Search narrows them; the other query fields are refused rather
// than silently ignored.
func (s *Service) listDeleted(ctx context.Context, q TargetQuery, limit int) (Page[TargetSummary], error) {
	if q.Tag != "" || len(q.States) > 0 || q.CSP != "" || q.SSLGrade != "" ||
		q.SSLBelow != "" || q.Port != 0 || q.ExpiringWithinDays != 0 || q.Expired || q.Sort != "" {
		return Page[TargetSummary]{}, invalid("deleted", "only search can be combined with deleted")
	}
	rows, err := s.st.ListDeletedTargets(ctx)
	if err != nil {
		return Page[TargetSummary]{}, err
	}
	now := time.Now()
	needle := strings.ToLower(q.Search)
	var matched []TargetSummary
	for _, t := range rows {
		if needle != "" && !strings.Contains(strings.ToLower(t.Input), needle) {
			continue
		}
		matched = append(matched, toSummary(t, now))
	}
	total := len(matched)
	if q.Offset >= total {
		return newPage[TargetSummary](nil, total, q.Offset), nil
	}
	end := min(q.Offset+limit, total)
	return newPage(matched[q.Offset:end], total, q.Offset), nil
}

// FindTargetByInput returns the id of the target whose input is name, after
// the same normalization an import applies. It finds soft-deleted targets too,
// so restore_target can name one; callers check liveness themselves. An
// unknown or unparsable name is ErrNotFound.
func (s *Service) FindTargetByInput(ctx context.Context, name string) (int, error) {
	normalized, _, ok := storage.NormalizeTarget(strings.TrimSpace(name))
	if !ok {
		return 0, ErrNotFound
	}
	id, err := s.client.Target.Query().
		Where(target.Input(normalized)).
		OnlyID(schema.SkipSoftDelete(ctx))
	if ent.IsNotFound(err) {
		return 0, ErrNotFound
	}
	return id, err
}

// GetTarget returns one live target with its newest scans. A missing or
// soft-deleted target is ErrNotFound.
func (s *Service) GetTarget(ctx context.Context, id int) (*TargetDetail, error) {
	now := time.Now()
	t, err := s.st.GetTargetBasic(ctx, id)
	if ent.IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	d := &TargetDetail{
		TargetSummary: toSummary(t, time.Now()),
		ResolveError:  t.ResolveError,
		ResolvedAt:    t.ResolvedAt,
		IPs:           []IPDetail{},
	}
	for _, i := range t.Edges.Ips {
		ipd := IPDetail{Address: i.Address}
		scans, _, err := s.st.GetIPScansPage(ctx, i.ID, 1, 0)
		if err != nil {
			return nil, err
		}
		if len(scans) > 0 {
			ipd.OpenPorts = portNumbers(scans[0])
			ipd.Error = scans[0].ScanError
			ipd.LastChecked = timePtr(scans[0].LastSeenAt)
			ipd.Stale = Stale(scans[0].LastSeenAt, s.intervals.Ports, now)
		}
		d.IPs = append(d.IPs, ipd)
	}
	slices.SortFunc(d.IPs, func(a, b IPDetail) int { return strings.Compare(a.Address, b.Address) })

	sc, failed, err := s.st.GetLatestSSL(ctx, t.Input)
	if err != nil {
		return nil, err
	}
	if sc != nil {
		d.SSL = &SSLDetail{
			Grade:           sc.Grade,
			Status:          sc.Status,
			CertSubject:     sc.CertSubject,
			CertIssuer:      sc.CertIssuer,
			CertExpiry:      timePtr(sc.CertExpiry),
			Protocols:       sc.Protocols,
			Vulnerabilities: sc.Vulnerabilities,
			CertProblems:    storage.CertProblems(sc.CertIssues),
			FirstSeen:       sc.ScannedAt,
			LastChecked:     sc.LastSeenAt,
		}
	}
	// The newest check failed: the result above stays, and the failure is
	// reported next to it (#61).
	if failed != nil {
		if d.SSL == nil {
			d.SSL = &SSLDetail{}
		}
		d.SSL.LastCheckError = strings.TrimPrefix(failed.Status, storage.SSLErrorPrefix)
		d.SSL.LastCheckFailedAt = timePtr(failed.LastSeenAt)
	}
	// Stale by the newest check, failed or not: a failure is a recent check.
	if d.SSL != nil && s.sslScanning {
		last := d.SSL.LastChecked
		if failed != nil {
			last = failed.LastSeenAt
		}
		d.SSL.Stale = Stale(last, s.intervals.SSL, now)
	}

	cspScans, _, err := s.st.GetCSPScansPage(ctx, id, 1, 0)
	if err != nil {
		return nil, err
	}
	if len(cspScans) > 0 {
		sc := cspScans[0]
		findings := make([]CSPFinding, 0, len(sc.Findings))
		for _, f := range sc.Findings {
			findings = append(findings, CSPFinding{Finding: f, Level: f.Severity.Level()})
		}
		d.CSP = &CSPDetail{
			Header:       sc.CspHeader,
			Findings:     findings,
			ProbeError:   sc.ProbeError,
			StatusCode:   sc.StatusCode,
			FinalURL:     sc.FinalURL,
			TLSProblem:   sc.TLSProblem,
			RedirectHost: sc.RedirectHost,
			FirstSeen:    sc.ScannedAt,
			LastChecked:  sc.LastSeenAt,
			Stale:        Stale(sc.LastSeenAt, s.intervals.CSP, now),
		}
	}
	return d, nil
}

// TargetHistory merges the SSL, CSP and port scan rows of a live target,
// newest first.
func (s *Service) TargetHistory(ctx context.Context, id, limit, offset int) (Page[HistoryEntry], error) {
	if offset < 0 {
		return Page[HistoryEntry]{}, invalid("offset", "must not be negative")
	}
	limit = clampLimit(limit, defaultLimit, maxLimit)
	t, err := s.st.GetTargetBasic(ctx, id)
	if ent.IsNotFound(err) {
		return Page[HistoryEntry]{}, ErrNotFound
	}
	if err != nil {
		return Page[HistoryEntry]{}, err
	}

	// Each kind is read one row past the page, so the row at the end of the
	// page can still be compared with the row before it. Any row that lands on
	// the page is among the first offset+limit of its kind, so this is enough.
	need := offset + limit + 1
	var all []HistoryEntry
	total := 0

	sslScans, n, err := s.st.GetSSLScansPage(ctx, id, need, 0)
	if err != nil {
		return Page[HistoryEntry]{}, err
	}
	total += n
	for k, sc := range sslScans {
		e := HistoryEntry{Kind: "ssl", FirstSeen: sc.ScannedAt, LastChecked: sc.LastSeenAt, Grade: sc.Grade}
		if storage.SSLCheckFailed(sc) {
			e.Summary = "SSL check failed"
			e.Error = strings.TrimPrefix(sc.Status, storage.SSLErrorPrefix)
			all = append(all, e)
			continue
		}
		// Compare with the previous result, skipping failed checks (#61).
		prev := -1
		for j := k + 1; j < len(sslScans); j++ {
			if !storage.SSLCheckFailed(sslScans[j]) {
				prev = j
				break
			}
		}
		if prev >= 0 {
			e.Summary = fmt.Sprintf("grade %s → %s", orNone(sslScans[prev].Grade), orNone(sc.Grade))
		} else {
			e.Summary = "grade " + orNone(sc.Grade)
		}
		all = append(all, e)
	}

	dnsRows, n, err := s.st.GetDNSChangesPage(ctx, id, need, 0)
	if err != nil {
		return Page[HistoryEntry]{}, err
	}
	total += n
	for _, dc := range dnsRows {
		all = append(all, HistoryEntry{Kind: "dns", FirstSeen: dc.ChangedAt, LastChecked: dc.ChangedAt, Summary: DNSChangeSummary(dc)})
	}

	cspScans, n, err := s.st.GetCSPScansPage(ctx, id, need, 0)
	if err != nil {
		return Page[HistoryEntry]{}, err
	}
	total += n
	for _, sc := range cspScans {
		e := HistoryEntry{Kind: "csp", FirstSeen: sc.ScannedAt, LastChecked: sc.LastSeenAt}
		if sc.RedirectHost != "" {
			e.Summary = "CSP not judged, redirects to " + sc.RedirectHost
		} else if code, ok := storage.CSPNoApp(sc); ok {
			e.Summary = fmt.Sprintf("CSP no application served (%d)", code)
		} else if sc.ProbeError != "" {
			e.Summary = "CSP " + cspNoResponse(sc.ProbeError)
			e.Error = sc.ProbeError
		} else {
			count := len(sc.Findings)
			e.FindingsCount = &count
			e.Summary = "CSP " + findingCount(count)
		}
		all = append(all, e)
	}

	for _, i := range t.Edges.Ips {
		scans, n, err := s.st.GetIPScansPage(ctx, i.ID, need, 0)
		if err != nil {
			return Page[HistoryEntry]{}, err
		}
		total += n
		for _, sc := range scans {
			e := HistoryEntry{Kind: "ports", IP: i.Address, FirstSeen: sc.ScannedAt, LastChecked: sc.LastSeenAt}
			ports := portNumbers(sc)
			switch {
			case sc.ScanError != "":
				e.Summary = "unreachable"
				e.Error = sc.ScanError
			case len(ports) == 0:
				e.Summary = "no open ports"
			default:
				e.Ports = ports
				e.Summary = "ports " + joinInts(ports)
			}
			all = append(all, e)
		}
	}

	slices.SortStableFunc(all, func(a, b HistoryEntry) int { return b.FirstSeen.Compare(a.FirstSeen) })
	if offset >= len(all) {
		return newPage[HistoryEntry](nil, total, offset), nil
	}
	end := min(offset+limit, len(all))
	return newPage(all[offset:end], total, offset), nil
}

// ListTags returns every tag with its live target count, by name.
func (s *Service) ListTags(ctx context.Context) ([]Tag, error) {
	rows, err := s.client.Tag.Query().
		WithTargets().
		Order(ent.Asc(tag.FieldName)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Tag, 0, len(rows))
	for _, t := range rows {
		out = append(out, Tag{
			ID:          t.ID,
			Name:        t.Name,
			Color:       t.Color,
			TargetCount: len(t.Edges.Targets),
		})
	}
	return out, nil
}

// toSummary builds the list view of t. Its tags must be loaded.
func toSummary(t *ent.Target, now time.Time) TargetSummary {
	tags := make([]string, 0, len(t.Edges.Tags))
	for _, g := range t.Edges.Tags {
		tags = append(tags, g.Name)
	}
	sum := TargetSummary{
		ID:           t.ID,
		Input:        t.Input,
		IsIP:         t.IsIP,
		Reachability: string(t.Reachability),
		Tags:         tags,
		SSLGrade:     t.LatestSslGrade,
		CertProblems: storage.CertProblems(t.LatestCertIssues),
		CertExpiry:   t.LatestCertExpiry,
		CSPFindings:  t.LatestCspFindingCount,
		OpenPorts:    t.OpenPortCount,
		CreatedAt:    t.CreateTime,
		DeletedAt:    t.DeletedAt,
	}
	if t.LatestCertExpiry != nil {
		// Whole days, truncated toward zero, as the dashboard badge shows them.
		days := int(t.LatestCertExpiry.Sub(now).Hours() / 24)
		sum.CertDaysLeft = &days
	}
	return sum
}

// portNumbers returns the open ports of a loaded scan, ascending.
func portNumbers(scan *ent.PortScan) []int {
	var out []int
	for _, p := range scan.Edges.Ports {
		out = append(out, p.Number)
	}
	slices.Sort(out)
	return out
}

func joinInts(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}

// orNone names an empty grade, which means the scan did not produce one.
func orNone(grade string) string {
	if grade == "" {
		return "none"
	}
	return grade
}

// timePtr returns &t, or nil for the zero time (a column that was never set).
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
