package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

type Job struct {
	ent.Schema
}

func (Job) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("type").Values("resolve", "port_scan", "ssl_scan", "csp_scan", "import"),
		field.Enum("status").Values("pending", "in_progress", "completed", "failed").Default("pending"),
		field.JSON("payload", map[string]any{}),
		field.JSON("result", map[string]any{}).Optional(),
		field.String("error").Optional().Nillable(),
		field.Time("started_at").Optional().Nillable(),
		field.Time("completed_at").Optional().Nillable(),
		field.Time("timeout_at").Optional().Nillable(),
	}
}

func (Job) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}
