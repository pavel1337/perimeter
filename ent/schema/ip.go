package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

// IP holds the schema definition for the IP entity.
type IP struct {
	ent.Schema
}

// Fields of the IP.
func (IP) Fields() []ent.Field {
	return []ent.Field{
		field.String("address").Unique().NotEmpty(),
	}
}

// Edges of the IP.
func (IP) Edges() []ent.Edge {
	return []ent.Edge{
		// An IP can belong to multiple targets (e.g. shared hosting)
		edge.From("targets", Target.Type).
			Ref("ips"),

		// An IP has many port scans
		edge.To("scans", PortScan.Type),
	}
}

// Mixin of the IP.
func (IP) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{}, // Adds created_at, updated_at
	}
}
