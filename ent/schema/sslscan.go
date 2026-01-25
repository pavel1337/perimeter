package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// SSLScan holds the schema definition for the SSLScan entity.
type SSLScan struct {
	ent.Schema
}

// Fields of the SSLScan.
func (SSLScan) Fields() []ent.Field {
	return []ent.Field{
		field.Time("scanned_at"),
		field.String("grade"),
		field.String("status"),
		field.String("cert_issuer").Optional(),
		field.String("cert_subject").Optional(),
		field.Time("cert_expiry").Optional(),
		field.JSON("protocols", []string{}).Optional(),
		field.JSON("vulnerabilities", []string{}).Optional(),
	}
}

// Edges of the SSLScan.
func (SSLScan) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("target", Target.Type).
			Ref("ssl_scans").
			Unique().
			Required(),
	}
}
