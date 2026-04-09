package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

type Tag struct {
	ent.Schema
}

func (Tag) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").Unique().NotEmpty(),
		field.String("color").Default("#6b7280"),
	}
}

func (Tag) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("targets", Target.Type).Ref("tags"),
	}
}
