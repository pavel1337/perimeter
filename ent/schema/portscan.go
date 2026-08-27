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
		// When this result was first observed.
		field.Time("scanned_at").Default(time.Now),
		// When this result was last confirmed unchanged.
		field.Time("last_seen_at").Optional(),
		// How many scans produced this same result. 0 means "not yet
		// collapsed"; the startup backfill uses it as its guard.
		field.Int("check_count").Default(0),
	}
}

func (PortScan) Edges() []ent.Edge {
	return []ent.Edge{
		// Link back to the IP
		edge.From("ip", IP.Type).
			Ref("scans").
			Unique().
			Required(),

		// Link to the specific ports found open in this scan
		edge.To("ports", Port.Type),
	}
}
