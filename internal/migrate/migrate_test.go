package migrate

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"perimeter/ent"
	"perimeter/ent/enttest"

	sqlite "modernc.org/sqlite"
)

func init() { sql.Register("sqlite3", &sqlite.Driver{}) }

func newClient(t *testing.T) *ent.Client {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:migrate?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	t.Cleanup(func() { client.Close() })
	return client
}

func TestRunAppliesEachMigrationOnce(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()

	var order []string
	ms := []Migration{
		{Name: "0001_a", Run: func(context.Context, *ent.Client) error { order = append(order, "a"); return nil }},
		{Name: "0002_b", Run: func(context.Context, *ent.Client) error { order = append(order, "b"); return nil }},
	}

	for range 2 {
		if err := run(ctx, client, ms); err != nil {
			t.Fatalf("run: %v", err)
		}
	}

	if len(order) != 2 || order[0] != "a" || order[1] != "b" {
		t.Errorf("ran %v, want [a b] exactly once", order)
	}
}

func TestRunStopsAtFailure(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()

	boom := errors.New("boom")
	ran := 0
	ms := []Migration{
		{Name: "0003_fails", Run: func(context.Context, *ent.Client) error { ran++; return boom }},
		{Name: "0004_never", Run: func(context.Context, *ent.Client) error { t.Error("later migration ran"); return nil }},
	}

	if err := run(ctx, client, ms); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}

	// Nothing recorded, so the next boot retries.
	if err := run(ctx, client, ms[:1]); !errors.Is(err, boom) {
		t.Fatalf("second run err = %v, want boom", err)
	}
	if ran != 2 {
		t.Errorf("failing migration ran %d times, want 2", ran)
	}
}
