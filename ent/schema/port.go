package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

type Port struct {
	ent.Schema
}

func (Port) Fields() []ent.Field {
	return []ent.Field{
		// The number: 80, 443, 22
		field.Int("number"),
	}
}

func (Port) Edges() []ent.Edge {
	return []ent.Edge{
		// Which scan found this port?
		edge.From("scan", PortScan.Type).
			Ref("ports").
			Unique().
			Required(),
	}
}
