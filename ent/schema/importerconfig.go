package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

type ImporterConfig struct {
	ent.Schema
}

func (ImporterConfig) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("provider").Values("manual", "dns_bruteforce"),
		field.Bytes("credentials"),
		field.Int64("sync_interval_seconds").Default(3600),
		field.Time("last_sync_at").Optional().Nillable(),
		field.Bool("enabled").Default(true),
	}
}

func (ImporterConfig) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}
