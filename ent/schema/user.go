package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

type User struct {
	ent.Schema
}

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("email").Unique().NotEmpty(),
		field.String("name").Default(""),
		field.String("password_hash").Optional().Nillable(),
		field.Bool("confirmed").Default(false),
		field.Enum("role").Values("admin", "member").Default("member"),
		field.Time("last_login_at").Optional().Nillable(),
	}
}

func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("targets", Target.Type),
		edge.To("sessions", Session.Type),
		edge.To("invites", Invite.Type),
	}
}

func (User) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}
