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
		field.Bool("is_ip").Default(false),
	}
}

func (Target) Edges() []ent.Edge {
	return []ent.Edge{
		// A target resolves to one or more IPs
		edge.To("ips", IP.Type),

		// A target has a history of other scans
		edge.To("ssl_scans", SSLScan.Type),
		edge.To("csp_scans", CSPScan.Type),
	}
}

func (Target) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{}, // Adds created_at, updated_at
	}
}
