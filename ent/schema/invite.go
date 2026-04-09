package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

type Invite struct {
	ent.Schema
}

func (Invite) Fields() []ent.Field {
	return []ent.Field{
		field.String("email").NotEmpty(),
		field.String("token_hash").Unique().NotEmpty(),
		field.Enum("role").Values("admin", "member").Default("member"),
		field.Time("expires_at"),
		field.Time("accepted_at").Optional().Nillable(),
	}
}

func (Invite) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("invited_by", User.Type).
			Ref("invites").
			Unique().
			Required(),
	}
}

func (Invite) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}
