package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

type Target struct {
	ent.Schema
}

func (Target) Fields() []ent.Field {
	return []ent.Field{
		// The distinct IP or Domain: "192.168.1.1" or "example.com"
		field.String("input").Unique().NotEmpty(),
	}
}

func (Target) Edges() []ent.Edge {
	return []ent.Edge{
		// A target has a history of many scans
		edge.To("scans", PortScan.Type),
	}
}

func (Target) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{}, // Adds created_at, updated_at
	}
}
