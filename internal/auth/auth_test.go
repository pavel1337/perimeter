package auth_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"perimeter/ent/enttest"
	"perimeter/ent/user"
	"perimeter/internal/auth"

	sqlite "modernc.org/sqlite"
)

// modernc.org/sqlite registers itself as "sqlite"; ent opens the "sqlite3"
// driver name, so alias it here. Pure-Go, no CGO.
func init() { sql.Register("sqlite3", &sqlite.Driver{}) }

func newTestAuth(t *testing.T) *auth.Auth {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	t.Cleanup(func() { client.Close() })

	a, err := auth.New(context.Background(), auth.Config{
		SessionMaxAge: 24 * time.Hour,
	}, client)
	if err != nil {
		t.Fatalf("failed to create auth: %v", err)
	}
	return a
}

func TestRegisterFirstUserIsAdmin(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if u.Role != user.RoleAdmin {
		t.Errorf("expected admin role, got %s", u.Role)
	}
}

func TestRegisterSecondUserRequiresInvite(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	// Create first user (admin)
	_, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register admin: %v", err)
	}

	// Second user without invite should fail
	_, err = a.Register(ctx, "user@test.com", "User", "password123")
	if err != auth.ErrNotAllowed {
		t.Errorf("expected ErrNotAllowed, got %v", err)
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	_, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, err = a.Register(ctx, "admin@test.com", "Admin2", "password456")
	if err != auth.ErrEmailTaken {
		t.Errorf("expected ErrEmailTaken, got %v", err)
	}
}

func TestLoginSuccess(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	_, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	u, err := a.Login(ctx, "admin@test.com", "password123")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if u.Email != "admin@test.com" {
		t.Errorf("expected admin@test.com, got %s", u.Email)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	_, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, err = a.Login(ctx, "admin@test.com", "wrongpassword")
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLoginNonexistentUser(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	_, err := a.Login(ctx, "nobody@test.com", "password")
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestSessionCreateAndValidate(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	token, err := a.CreateSession(ctx, u)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	found, err := a.ValidateSession(ctx, token)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if found.ID != u.ID {
		t.Errorf("expected user ID %d, got %d", u.ID, found.ID)
	}
}

func TestSessionDelete(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	token, err := a.CreateSession(ctx, u)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	err = a.DeleteSession(ctx, token)
	if err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	_, err = a.ValidateSession(ctx, token)
	if err == nil {
		t.Error("expected error after session deletion")
	}
}

func TestInviteFlow(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	admin, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register admin: %v", err)
	}

	token, err := a.CreateInvite(ctx, admin, "user@test.com", user.RoleMember)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	inv, err := a.ValidateInviteToken(ctx, token)
	if err != nil {
		t.Fatalf("ValidateInviteToken: %v", err)
	}
	if inv.Email != "user@test.com" {
		t.Errorf("expected user@test.com, got %s", inv.Email)
	}

	u, err := a.Register(ctx, "user@test.com", "User", "password456")
	if err != nil {
		t.Fatalf("Register invited user: %v", err)
	}
	if u.Role != user.RoleMember {
		t.Errorf("expected member role, got %s", u.Role)
	}
}

func TestHasUsers(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	has, err := a.HasUsers(ctx)
	if err != nil {
		t.Fatalf("HasUsers: %v", err)
	}
	if has {
		t.Error("expected no users")
	}

	_, err = a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	has, err = a.HasUsers(ctx)
	if err != nil {
		t.Fatalf("HasUsers: %v", err)
	}
	if !has {
		t.Error("expected users to exist")
	}
}
