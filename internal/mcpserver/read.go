package mcpserver

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"perimeter/internal/service"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// readOnly is the annotation of every read tool: it changes nothing, repeats
// have no further effect, and it reaches no outside system.
var readOnly = &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(false)}

// addReadTools registers the tools every caller gets.
func (t *toolset) addReadTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "summary",
		Description: "Overall posture of all tracked targets: totals by reachability, open ports, CSP issues, certificates expiring soon or already expired, the weakest SSL grades, the soonest certificate expiries, and changes from the last 7 days. Call this first. Data comes from periodic scans and can be hours old.",
		Annotations: readOnly,
	}, t.summary)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_targets",
		Description: "List targets, one line each. Filters combine with AND: for example ssl_below B finds weak TLS, and expiring_within_days 14 finds certificates about to expire. Lists hold 25 targets by default, at most 100; when more exist the text says which offset to pass next. Set deleted to list soft-deleted targets instead.",
		Annotations: readOnly,
	}, t.listTargets)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_target",
		Description: "Full detail of one target: its reachability state and tags, its IP addresses with open ports, the newest SSL scan (grade, certificate expiry and issuer) and the newest CSP evaluation with a line per finding (level, directive, value, description), and when each scan last ran. target is an id such as 12 or a name such as example.com.",
		Annotations: readOnly,
	}, t.getTarget)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "target_history",
		Description: "Scan history of one target, newest first: SSL grade changes, CSP results and port scans. target is an id or a name. Pages of 25 by default, at most 100.",
		Annotations: readOnly,
	}, t.targetHistory)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "find_issues",
		Description: "Find targets that need attention, grouped by category, each with a one-line reason. Categories: weak_ssl (SSL grade worse than B), expiring_certs (certificate expires within expiring_within_days, default the server window; expired ones are included), expired_certs, csp_issues, unreachable, unresolved, and open_port (needs port). With no categories, every category except open_port is checked. limit and offset apply to each category.",
		Annotations: readOnly,
	}, t.findIssues)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "changes_since",
		Description: "Changes seen after a time, oldest first: targets added or deleted, SSL grade changes, certificate renewals, ports opened or closed, CSP changes, and reachability changes. since is an RFC 3339 time such as 2026-10-11T00:00:00Z, or a duration back from now such as 24h or 7d. The reply gives until: the time of the last change, or since when there is none. To page through or poll for new results, call again with since set to until.",
		Annotations: readOnly,
	}, t.changesSince)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_tags",
		Description: "Every tag, with the number of live targets carrying it.",
		Annotations: readOnly,
	}, t.listTags)
}

type listTargetsIn struct {
	Query              string `json:"query,omitempty" jsonschema:"Keep targets whose input contains this text, ignoring case."`
	Tag                string `json:"tag,omitempty" jsonschema:"Keep targets carrying this tag name."`
	State              string `json:"state,omitempty" jsonschema:"Keep targets in this reachability state: ok, unreachable, unresolved or pending."`
	SSLBelow           string `json:"ssl_below,omitempty" jsonschema:"Keep targets whose SSL grade is worse than this one. B keeps C, D, E, F and so on. Ungraded targets are not kept."`
	Port               int    `json:"port,omitempty" jsonschema:"Keep targets with this TCP port open on one of their IP addresses, 1 to 65535."`
	CSP                string `json:"csp,omitempty" jsonschema:"CSP filter: issues (has findings), ok (no findings) or none (never checked)."`
	ExpiringWithinDays int    `json:"expiring_within_days,omitempty" jsonschema:"Keep targets whose certificate expires within this many days. Expired certificates are included."`
	Deleted            bool   `json:"deleted,omitempty" jsonschema:"List soft-deleted targets instead, most recently deleted first. Only query can be combined with it."`
	Sort               string `json:"sort,omitempty" jsonschema:"Sort field: target (default, by name), csp, ports, ssl (best grade first) or expiry (soonest first)."`
	Desc               bool   `json:"desc,omitempty" jsonschema:"Reverse the sort order."`
	Limit              int    `json:"limit,omitempty" jsonschema:"Targets per page. Default 25, at most 100."`
	Offset             int    `json:"offset,omitempty" jsonschema:"Number of targets to skip, to read the next page."`
}

func (t *toolset) listTargets(ctx context.Context, _ *mcp.CallToolRequest, in listTargetsIn) (*mcp.CallToolResult, service.Page[service.TargetSummary], error) {
	q := service.TargetQuery{
		Search:             in.Query,
		Tag:                in.Tag,
		SSLBelow:           in.SSLBelow,
		CSP:                in.CSP,
		Port:               in.Port,
		ExpiringWithinDays: in.ExpiringWithinDays,
		Deleted:            in.Deleted,
		Sort:               in.Sort,
		Desc:               in.Desc,
		Limit:              pageLimit(in.Limit),
		Offset:             in.Offset,
	}
	if in.State != "" {
		q.States = []string{in.State}
	}
	page, err := t.svc.ListTargets(ctx, q)
	if err != nil {
		return nil, page, err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d of %d targets", len(page.Items), page.Total)
	for _, s := range page.Items {
		b.WriteString("\n" + targetLine(s))
	}
	if more := moreText(page.Total, in.Offset, len(page.Items)); more != "" {
		b.WriteString("\n" + more)
	}
	return reply(b.String(), page)
}

type targetIn struct {
	Target string `json:"target" jsonschema:"The target: a numeric id such as 12, or the name of the target such as example.com."`
}

func (t *toolset) getTarget(ctx context.Context, _ *mcp.CallToolRequest, in targetIn) (*mcp.CallToolResult, service.TargetDetail, error) {
	id, err := t.targetID(ctx, in.Target)
	if err != nil {
		return nil, service.TargetDetail{}, err
	}
	d, err := t.svc.GetTarget(ctx, id)
	if err != nil {
		return nil, service.TargetDetail{}, notFound(in.Target, "live target", err)
	}

	var b strings.Builder
	b.WriteString(targetLine(d.TargetSummary))
	fmt.Fprintf(&b, "\nstate: %s", d.Reachability)
	if d.ResolveError != "" {
		b.WriteString("\nresolve error: " + d.ResolveError)
	}
	if d.ResolvedAt != nil {
		fmt.Fprintf(&b, "\nresolved at: %s", formatTime(*d.ResolvedAt))
	}
	for _, ip := range d.IPs {
		fmt.Fprintf(&b, "\nIP %s: %s", ip.Address, portsText(ip))
		if ip.LastChecked != nil {
			fmt.Fprintf(&b, " (checked %s)", formatTime(*ip.LastChecked))
		}
	}
	switch {
	case d.SSL == nil:
		b.WriteString("\nSSL: not scanned")
	case d.SSL.FirstSeen.IsZero():
		// Only failed checks so far.
		b.WriteString("\nSSL: no result yet")
	default:
		fmt.Fprintf(&b, "\nSSL: grade %s (%s)", orDash(d.SSL.Grade), d.SSL.Status)
		if d.SSL.CertIssuer != "" {
			b.WriteString(", issuer " + d.SSL.CertIssuer)
		}
		if d.SSL.CertExpiry != nil {
			fmt.Fprintf(&b, ", expires %s", d.SSL.CertExpiry.UTC().Format("2006-01-02"))
		}
		if len(d.SSL.Vulnerabilities) > 0 {
			b.WriteString(", vulnerabilities: " + strings.Join(d.SSL.Vulnerabilities, ", "))
		}
		fmt.Fprintf(&b, " (checked %s)", formatTime(d.SSL.LastChecked))
	}
	if d.SSL != nil && d.SSL.LastCheckError != "" {
		fmt.Fprintf(&b, "\nSSL last check failed")
		if d.SSL.LastCheckFailedAt != nil {
			fmt.Fprintf(&b, " %s", formatTime(*d.SSL.LastCheckFailedAt))
		}
		if !d.SSL.FirstSeen.IsZero() {
			b.WriteString("; the grade above is the last real result")
		}
		b.WriteString(". Error: " + d.SSL.LastCheckError)
	}
	switch {
	case d.CSP == nil:
		b.WriteString("\nCSP: not checked")
	case d.CSP.ProbeError != "":
		fmt.Fprintf(&b, "\nCSP: no response: %s (checked %s)", d.CSP.ProbeError, formatTime(d.CSP.LastChecked))
	case d.CSP.StatusCode != 0 && d.CSP.StatusCode/100 != 2:
		fmt.Fprintf(&b, "\nCSP: not judged, no application served (HTTP %d", d.CSP.StatusCode)
		if d.CSP.FinalURL != "" {
			b.WriteString(" at " + d.CSP.FinalURL)
		}
		fmt.Fprintf(&b, ", checked %s)", formatTime(d.CSP.LastChecked))
	default:
		b.WriteString("\n" + cspText(len(d.CSP.Findings)) + " (checked " + formatTime(d.CSP.LastChecked) + ")")
		for _, f := range d.CSP.Findings {
			b.WriteString("\n" + cspFindingLine(f))
		}
	}
	return reply(b.String(), *d)
}

// cspFindingLine is one CSP finding: level, directive, value, short
// description; empty parts are left out.
func cspFindingLine(f service.CSPFinding) string {
	line := "- " + f.Level
	if f.Directive != "" {
		line += " " + f.Directive
	}
	if f.Value != "" {
		line += " " + f.Value
	}
	return line + ": " + f.Description
}

// portsText describes one IP of a target in a detail reply.
func portsText(ip service.IPDetail) string {
	switch {
	case ip.Error != "":
		return "unreachable: " + ip.Error
	case len(ip.OpenPorts) == 0:
		return "no open ports"
	}
	parts := make([]string, 0, len(ip.OpenPorts))
	for _, p := range ip.OpenPorts {
		parts = append(parts, strconv.Itoa(p))
	}
	return "open ports " + strings.Join(parts, ", ")
}

// orDash stands in for a grade the scan did not produce.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type targetHistoryIn struct {
	Target string `json:"target" jsonschema:"The target: a numeric id such as 12, or the name of the target such as example.com."`
	Limit  int    `json:"limit,omitempty" jsonschema:"Entries per page. Default 25, at most 100."`
	Offset int    `json:"offset,omitempty" jsonschema:"Number of entries to skip, to read the next page."`
}

func (t *toolset) targetHistory(ctx context.Context, _ *mcp.CallToolRequest, in targetHistoryIn) (*mcp.CallToolResult, service.Page[service.HistoryEntry], error) {
	id, err := t.targetID(ctx, in.Target)
	if err != nil {
		return nil, service.Page[service.HistoryEntry]{}, err
	}
	page, err := t.svc.TargetHistory(ctx, id, pageLimit(in.Limit), in.Offset)
	if err != nil {
		return nil, page, notFound(in.Target, "live target", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d of %d entries", len(page.Items), page.Total)
	for _, e := range page.Items {
		kind := e.Kind
		if e.IP != "" {
			kind += " " + e.IP
		}
		fmt.Fprintf(&b, "\n%s · %s: %s", formatTime(e.FirstSeen), kind, e.Summary)
	}
	if more := moreText(page.Total, in.Offset, len(page.Items)); more != "" {
		b.WriteString("\n" + more)
	}
	return reply(b.String(), page)
}

// Issue categories, in the order they are reported.
const (
	issueWeakSSL     = "weak_ssl"
	issueExpiring    = "expiring_certs"
	issueExpired     = "expired_certs"
	issueCSP         = "csp_issues"
	issueUnreachable = "unreachable"
	issueUnresolved  = "unresolved"
	issueOpenPort    = "open_port"
)

var issueCategories = []string{issueWeakSSL, issueExpiring, issueExpired, issueCSP, issueUnreachable, issueUnresolved, issueOpenPort}

type issuesIn struct {
	Categories         []string `json:"categories,omitempty" jsonschema:"Categories to check: weak_ssl, expiring_certs, expired_certs, csp_issues, unreachable, unresolved, open_port. Leave out to check all but open_port."`
	ExpiringWithinDays int      `json:"expiring_within_days,omitempty" jsonschema:"For expiring_certs: the window in days. Default is the server's certificate expiry window."`
	Port               int      `json:"port,omitempty" jsonschema:"For open_port: the TCP port to look for, 1 to 65535."`
	Limit              int      `json:"limit,omitempty" jsonschema:"Targets per category. Default 25, at most 100."`
	Offset             int      `json:"offset,omitempty" jsonschema:"Number of targets to skip in each category, to read the next page."`
}

// IssueGroup is one category of find_issues with its matching targets.
type IssueGroup struct {
	Category   string        `json:"category"`
	Total      int           `json:"total"`
	Targets    []IssueTarget `json:"targets"`
	NextOffset *int          `json:"next_offset,omitempty"`
}

// IssueTarget is a target matching a category, with the reason it matched.
type IssueTarget struct {
	ID     int    `json:"id"`
	Input  string `json:"input"`
	Reason string `json:"reason"`
}

// IssuesOut is the reply of find_issues.
type IssuesOut struct {
	Groups []IssueGroup `json:"groups"`
}

func (t *toolset) findIssues(ctx context.Context, _ *mcp.CallToolRequest, in issuesIn) (*mcp.CallToolResult, IssuesOut, error) {
	wanted, err := issueSelection(in.Categories)
	if err != nil {
		return nil, IssuesOut{}, err
	}
	if slices.Contains(wanted, issueOpenPort) && in.Port <= 0 {
		return nil, IssuesOut{}, badArg("port", "is required with open_port: the TCP port to look for")
	}
	days := in.ExpiringWithinDays
	if days == 0 {
		days = int(t.svc.CertExpiryWindow() / (24 * time.Hour))
	}

	limit := pageLimit(in.Limit)
	out := IssuesOut{Groups: []IssueGroup{}}
	var b strings.Builder
	for _, cat := range wanted {
		q, reason, ok := issueQuery(cat, days, in.Port)
		if !ok {
			// A window of zero days (the expiry window is disabled) matches
			// nothing, as it does on the dashboard.
			out.Groups = append(out.Groups, IssueGroup{Category: cat, Targets: []IssueTarget{}})
			fmt.Fprintf(&b, "%s: none\n", cat)
			continue
		}
		q.Limit = limit
		q.Offset = in.Offset
		page, err := t.svc.ListTargets(ctx, q)
		if err != nil {
			return nil, IssuesOut{}, err
		}
		g := IssueGroup{Category: cat, Total: page.Total, Targets: []IssueTarget{}, NextOffset: page.NextOffset}
		for _, s := range page.Items {
			g.Targets = append(g.Targets, IssueTarget{ID: s.ID, Input: s.Input, Reason: reason(s)})
		}
		out.Groups = append(out.Groups, g)

		if page.Total == 0 {
			fmt.Fprintf(&b, "%s: none\n", cat)
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", cat, countNoun(page.Total, "target"))
		for _, it := range g.Targets {
			fmt.Fprintf(&b, "  #%d %s: %s\n", it.ID, it.Input, it.Reason)
		}
		if more := moreText(page.Total, in.Offset, len(page.Items)); more != "" {
			fmt.Fprintf(&b, "  %s\n", more)
		}
	}
	return reply(strings.TrimRight(b.String(), "\n"), out)
}

// issueSelection validates the requested categories and returns them in
// report order. None requested means every category but open_port.
func issueSelection(requested []string) ([]string, error) {
	if len(requested) == 0 {
		var all []string
		for _, c := range issueCategories {
			if c != issueOpenPort {
				all = append(all, c)
			}
		}
		return all, nil
	}
	for _, c := range requested {
		if !slices.Contains(issueCategories, c) {
			return nil, badArg("categories", "unknown category %q; use one of %s", c, strings.Join(issueCategories, ", "))
		}
	}
	var out []string
	for _, c := range issueCategories {
		if slices.Contains(requested, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// issueQuery is the target query behind one category, the reason shown for
// each match, and whether the category can match anything at all.
func issueQuery(cat string, days, port int) (service.TargetQuery, func(service.TargetSummary) string, bool) {
	switch cat {
	case issueWeakSSL:
		return service.TargetQuery{SSLBelow: "B", Sort: "ssl", Desc: true},
			func(s service.TargetSummary) string { return "SSL grade " + s.SSLGrade }, true
	case issueExpiring:
		if days <= 0 {
			return service.TargetQuery{}, nil, false
		}
		return service.TargetQuery{ExpiringWithinDays: days, Sort: "expiry"}, certReason, true
	case issueExpired:
		return service.TargetQuery{Expired: true, Sort: "expiry"}, certReason, true
	case issueCSP:
		return service.TargetQuery{CSP: "issues", Sort: "csp", Desc: true},
			func(s service.TargetSummary) string {
				if s.CSPFindings == nil {
					return "CSP findings"
				}
				return cspText(*s.CSPFindings)
			}, true
	case issueUnreachable:
		return service.TargetQuery{States: []string{"unreachable"}}, stateReason, true
	case issueUnresolved:
		return service.TargetQuery{States: []string{"unresolved"}}, stateReason, true
	default: // issueOpenPort
		return service.TargetQuery{Port: port},
			func(service.TargetSummary) string { return fmt.Sprintf("port %d open", port) }, true
	}
}

// certReason says when a certificate expires, or how long ago it did.
func certReason(s service.TargetSummary) string {
	if c := certText(s); c != "" {
		return c
	}
	return "certificate known"
}

// stateReason names the reachability state of a target.
func stateReason(s service.TargetSummary) string {
	return "state " + s.Reachability
}

type changesIn struct {
	Since string `json:"since" jsonschema:"Start of the window: an RFC 3339 time such as 2026-10-11T00:00:00Z, or a duration back from now such as 24h or 7d."`
	Limit int    `json:"limit,omitempty" jsonschema:"Changes per call. Default 25, at most 100."`
}

// ChangesOut is the reply of changes_since. Until is the time of the last
// change, or since when there is none, so the next poll starting there misses
// nothing that was being written while this one ran.
type ChangesOut struct {
	Changes   []service.Change `json:"changes"`
	Until     time.Time        `json:"until"`
	Truncated bool             `json:"truncated,omitempty"`
}

func (t *toolset) changesSince(ctx context.Context, _ *mcp.CallToolRequest, in changesIn) (*mcp.CallToolResult, ChangesOut, error) {
	now := time.Now()
	since, err := parseSince(in.Since, now)
	if err != nil {
		return nil, ChangesOut{}, err
	}
	changes, truncated, err := t.svc.ChangesSince(ctx, since, pageLimit(in.Limit))
	if err != nil {
		return nil, ChangesOut{}, err
	}
	out := ChangesOut{Changes: changes, Until: since, Truncated: truncated}
	if out.Changes == nil {
		out.Changes = []service.Change{}
	}
	if len(changes) > 0 {
		out.Until = changes[len(changes)-1].At
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s since %s", countNoun(len(changes), "change"), formatTime(since))
	for _, c := range changes {
		fmt.Fprintf(&b, "\n%s · %s · %s", formatTime(c.At), c.Target, c.Summary)
	}
	if truncated {
		fmt.Fprintf(&b, "\nmore follow; call again with since=%s", out.Until.UTC().Format(time.RFC3339Nano))
	} else {
		fmt.Fprintf(&b, "\nnext poll: since=%s", out.Until.UTC().Format(time.RFC3339Nano))
	}
	return reply(b.String(), out)
}

// parseSince reads an RFC 3339 time, or a duration back from now written as
// Go's time.ParseDuration does (24h) or in whole days (7d).
func parseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n >= 0 {
			return now.Add(-time.Duration(n) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, badArg("since", "use an RFC 3339 time such as 2026-10-11T00:00:00Z, or a duration such as 24h or 7d, not %q", s)
}

// TagsOut is the reply of list_tags.
type TagsOut struct {
	Tags []service.Tag `json:"tags"`
}

func (t *toolset) listTags(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, TagsOut, error) {
	tags, err := t.svc.ListTags(ctx)
	if err != nil {
		return nil, TagsOut{}, err
	}
	var b strings.Builder
	b.WriteString(countNoun(len(tags), "tag"))
	for _, g := range tags {
		fmt.Fprintf(&b, "\n%s: %s", g.Name, countNoun(g.TargetCount, "target"))
	}
	return reply(b.String(), TagsOut{Tags: tags})
}

// SummaryOut is the reply of summary: the service summary plus the weakest
// SSL grades, which show the worst issues by name.
type SummaryOut struct {
	service.Summary
	WorstSSL []service.TargetSummary `json:"worst_ssl"`
}

// worstSSLSize is how many weakest-graded targets summary names.
const worstSSLSize = 5

func (t *toolset) summary(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, SummaryOut, error) {
	now := time.Now()
	sum, err := t.svc.Summary(ctx, now)
	if err != nil {
		return nil, SummaryOut{}, err
	}
	worst, err := t.svc.ListTargets(ctx, service.TargetQuery{
		SSLBelow: "B", Sort: "ssl", Desc: true, Limit: worstSSLSize,
	})
	if err != nil {
		return nil, SummaryOut{}, err
	}
	out := SummaryOut{Summary: *sum, WorstSSL: worst.Items}
	if out.WorstSSL == nil {
		out.WorstSSL = []service.TargetSummary{}
	}

	tot := sum.Totals
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d ok, %d unreachable, %d unresolved, %d pending\n",
		countNoun(tot.Targets, "target"), tot.ByReachability["ok"], tot.ByReachability["unreachable"],
		tot.ByReachability["unresolved"], tot.ByReachability["pending"])
	fmt.Fprintf(&b, "certificates: %d expiring within %d days, %d expired; weak SSL (below B): %d; open ports: %d; CSP issues: %d\n",
		tot.ExpiringCerts, int(t.svc.CertExpiryWindow()/(24*time.Hour)), tot.ExpiredCerts,
		tot.WeakSSL, tot.OpenPorts, tot.CSPIssues)
	// Say so instead of zero counts reading as "all clean".
	if !sum.SSLScanning {
		b.WriteString("SSL scanning is off on this server, so SSL grades and certificate expiry are not checked.\n")
	} else if tot.SSLUnscanned > 0 {
		fmt.Fprintf(&b, "SSL not scanned yet: %s\n", countNoun(tot.SSLUnscanned, "target"))
	}
	if len(out.WorstSSL) > 0 {
		b.WriteString("weakest SSL:\n")
		for _, s := range out.WorstSSL {
			b.WriteString("  " + targetLine(s) + "\n")
		}
	}
	if len(sum.Expiring) > 0 {
		b.WriteString("soonest certificate expiries:\n")
		for _, s := range sum.Expiring {
			b.WriteString("  " + targetLine(s) + "\n")
		}
	}
	if len(sum.RecentChanges) > 0 {
		b.WriteString("recent changes, newest first:\n")
		for _, c := range sum.RecentChanges {
			fmt.Fprintf(&b, "  %s · %s · %s\n", formatTime(c.At), c.Target, c.Summary)
		}
	}
	return reply(strings.TrimRight(b.String(), "\n"), out)
}
