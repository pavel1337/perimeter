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
