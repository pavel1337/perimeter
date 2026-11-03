package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

type Target struct {
	ent.Schema
}

func (Target) Fields() []ent.Field {
	return []ent.Field{
		// The distinct IP or Domain: "192.168.1.1" or "example.com"
		field.String("input").Unique().NotEmpty(),
		field.Bool("is_ip").Default(false),
		// Resolution backoff state (see scanner.resolveBackoff).
		field.Int("resolve_attempts").Default(0),
		field.String("resolve_error").Optional(),
		// On-demand rescan (storage.RequestRescan). The request time drives
		// the cooldown and the "Rescan requested" note; the pending flags make
		// the SSL and CSP producers pick this target next, until a result is
		// stored.
		field.Time("rescan_requested_at").Optional().Nillable(),
		field.Bool("ssl_rescan_pending").Default(false),
		field.Bool("csp_rescan_pending").Default(false),
		// Whether the target answers at all, kept current by the scan write
		// paths so it can be filtered and sorted on in SQL (issue #15).
		field.Enum("reachability").
			Values("pending", "ok", "unresolved", "unreachable").
			Default("pending"),

		// Summary of the newest scans, so the dashboard can sort, filter and
		// paginate in SQL (issue #14). A cache: the scan tables stay
		// authoritative, and storage.refreshSummary rebuilds it from them on
		// every scan write. Nil means unknown: never scanned, or the scan
		// produced no value.
		field.String("latest_ssl_grade").Optional(),
		// latest_ssl_grade ordered best-first: A+ highest, ungraded 0.
		field.Int("latest_ssl_grade_rank").Default(0),
		field.Time("latest_cert_expiry").Optional().Nillable(),
		// Nil when no HTTP response has been evaluated yet.
		field.Int("latest_csp_finding_count").Optional().Nillable(),
		// Summed over the newest port scan of each of the target's IPs.
		field.Int("open_port_count").Default(0),
		// resolved_at is the clock for the re-resolution schedule: every live
		// target is re-resolved on RESOLVE_INTERVAL, tracked here rather than on
		// update_time, which changes on every row update (issue #59). It is
		// appended last so existing field indices are not shifted.
		field.Time("resolved_at").Optional().Nillable(),
	}
}

func (Target) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("reachability"),
		index.Fields("latest_ssl_grade_rank"),
		index.Fields("latest_cert_expiry"),
		index.Fields("latest_csp_finding_count"),
		index.Fields("open_port_count"),
	}
}

func (Target) Edges() []ent.Edge {
	return []ent.Edge{
		// A target resolves to one or more IPs
		edge.To("ips", IP.Type),

		// A target has a history of other scans
		edge.To("ssl_scans", SSLScan.Type),
		edge.To("csp_scans", CSPScan.Type),

		// Who added this target
		edge.From("owner", User.Type).
			Ref("targets").
			Unique(),

		// Tags for grouping
		edge.To("tags", Tag.Type),
	}
}

func (Target) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{}, // Adds created_at, updated_at
		SoftDeleteMixin{},
	}
}
