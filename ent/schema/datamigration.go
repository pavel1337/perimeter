package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// DataMigration is the ledger of data migrations that have already run. Schema
// DDL is still Ent auto-migration's job; this only tracks the one-off data
// rewrites in internal/migrate.
type DataMigration struct {
	ent.Schema
}

func (DataMigration) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").Unique(),
		field.Time("applied_at").Default(time.Now),
	}
}
