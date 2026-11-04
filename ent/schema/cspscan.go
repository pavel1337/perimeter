package schema

import (
	"perimeter/scanner/csp"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// CSPScan holds the schema definition for the CSPScan entity.
type CSPScan struct {
	ent.Schema
}

// Fields of the CSPScan.
func (CSPScan) Fields() []ent.Field {
	return []ent.Field{
		field.Time("scanned_at"),
		field.Time("last_seen_at").Optional(),
		field.Int("check_count").Default(0),
		field.String("csp_header"),
		field.JSON("findings", []csp.Finding{}).Optional(),
		// Why the probe got no HTTP response; empty when it got one. An
		// unreachable target has no header to evaluate, so it has no findings.
		field.String("probe_error").Optional(),
		// The HTTP status of the response and the URL it came from, after
		// redirects, without query or fragment (issue #67). CSP is judged on
		// 2xx responses only. 0 on rows stored before #67 and on probe errors.
		field.Int("status_code").Optional(),
		field.String("final_url").Optional(),
		// Why the certificate failed verification when the probe had to
		// skip it to read the response, e.g. "certificate not trusted:
		// self-signed or unknown issuer" (issue #68). Empty when it verified.
		field.String("tls_problem").Optional(),
		// The host a target redirects to when that is another site, e.g. an
		// OAuth provider's sign-in page. The probe stops there: the other
		// site's policy isn't the target's, so there are no findings (#70).
		field.String("redirect_host").Optional(),
	}
}

// Edges of the CSPScan.
func (CSPScan) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("target", Target.Type).
			Ref("csp_scans").
			Unique().
			Required(),
	}
}
