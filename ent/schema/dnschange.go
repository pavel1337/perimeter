package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// DNSChange is a re-resolve of a target that changed something: IPs added
// or removed, the name no longer resolving, or resolving again (issue #74).
// Link changes create no scan rows, so without these a moved or removed
// record left no trace in the history or the changes feed.
type DNSChange struct {
	ent.Schema
}

func (DNSChange) Fields() []ent.Field {
	return []ent.Field{
		field.Time("changed_at"),
		// changed: the set of IPs changed; gone: NXDOMAIN or NODATA after
		// the name resolved; back: it resolves again after that.
		field.Enum("kind").Values("changed", "gone", "back"),
		field.JSON("added", []string{}).Optional(),
		field.JSON("removed", []string{}).Optional(),
		// How many of the old IPs the new answer kept. Names behind CDNs
		// rotate some of their IPs all the time; a change that kept none is
		// a move.
		field.Int("kept").Default(0),
	}
}

func (DNSChange) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("target", Target.Type).
			Ref("dns_changes").
			Unique().
			Required(),
	}
}

func (DNSChange) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("changed_at"),
	}
}
