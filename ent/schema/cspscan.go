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
		field.String("csp_header"),
		field.JSON("findings", []csp.Finding{}).Optional(),
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
