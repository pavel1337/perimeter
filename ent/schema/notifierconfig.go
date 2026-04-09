package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

type NotifierConfig struct {
	ent.Schema
}

func (NotifierConfig) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("provider").Values("webhook"),
		field.Bytes("config"),
		field.Bool("enabled").Default(true),
	}
}

func (NotifierConfig) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}
