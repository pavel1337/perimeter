package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

type PortScan struct {
	ent.Schema
}

func (PortScan) Fields() []ent.Field {
	return []ent.Field{
		// When did this specific scan happen?
		field.Time("scanned_at").Default(time.Now),
	}
}

func (PortScan) Edges() []ent.Edge {
	return []ent.Edge{
		// Link back to the parent Target
		// Link back to parent Targets (Many-to-Many now, as multiple targets can share a scan if they resolve to same IP)
		edge.From("targets", Target.Type).
			Ref("scans").
			Required(),

		// Link to the specific ports found open in this scan
		edge.To("ports", Port.Type),
	}
}
