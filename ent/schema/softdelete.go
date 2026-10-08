package schema

import (
	"context"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"

	"perimeter/ent/intercept"
)

// SoftDeleteMixin adds deleted_at and hides rows that have it set from every
// query of the schema, eager loads and counts included (issue #19). Reading
// deleted rows is an explicit opt-in through SkipSoftDelete.
//
// Only queries are intercepted. Update and delete builders, and edge
// predicates from other schemas (ip.HasTargets), still see deleted rows, so
// those callers filter on deleted_at themselves.
type SoftDeleteMixin struct {
	mixin.Schema
}

func (SoftDeleteMixin) Fields() []ent.Field {
	return []ent.Field{
		field.Time("deleted_at").Optional().Nillable(),
	}
}

func (SoftDeleteMixin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("deleted_at"),
	}
}

type softDeleteKey struct{}

// SkipSoftDelete returns a context whose queries include soft-deleted rows.
func SkipSoftDelete(parent context.Context) context.Context {
	return context.WithValue(parent, softDeleteKey{}, true)
}

func (d SoftDeleteMixin) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{
		intercept.TraverseFunc(func(ctx context.Context, q intercept.Query) error {
			if skip, _ := ctx.Value(softDeleteKey{}).(bool); skip {
				return nil
			}
			q.WhereP(sql.FieldIsNull("deleted_at"))
			return nil
		}),
	}
}
