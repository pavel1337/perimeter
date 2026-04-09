package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"perimeter/ent"
	"perimeter/ent/invite"
	"perimeter/ent/session"
	"perimeter/ent/user"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrNotAllowed         = errors.New("registration is invite-only")
	ErrEmailTaken         = errors.New("email already registered")
)

// Config holds authentication configuration.
type Config struct {
	// Session
	SessionMaxAge time.Duration

	// OIDC (optional — leave Issuer empty to disable)
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string

	// Email confirmation (not yet implemented)
	RequireConfirm bool
}

// OIDCEnabled returns whether OIDC is configured.
func (c *Config) OIDCEnabled() bool {
	return c.OIDCIssuer != ""
}

// Auth handles authentication and session management.
type Auth struct {
	config   Config
	client   *ent.Client
	provider *oidc.Provider
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// New creates a new Auth instance. If OIDC is configured, it contacts the issuer for discovery.
func New(ctx context.Context, cfg Config, client *ent.Client) (*Auth, error) {
	a := &Auth{
		config: cfg,
		client: client,
	}

	if cfg.OIDCEnabled() {
		provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
		}
		a.provider = provider
		a.oauth = &oauth2.Config{
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			RedirectURL:  cfg.OIDCRedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		}
		a.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID})
	}

	return a, nil
}

// OIDCEnabled returns whether OIDC is available.
func (a *Auth) OIDCEnabled() bool {
	return a.config.OIDCEnabled()
}

// HasUsers returns whether any users exist in the database.
func (a *Auth) HasUsers(ctx context.Context) (bool, error) {
	count, err := a.client.User.Query().Count(ctx)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// --- Email + Password ---

// Register creates the first admin user or an invited user with email+password.
func (a *Auth) Register(ctx context.Context, email, name, password string) (*ent.User, error) {
	// Check if email is already taken
	exists, err := a.client.User.Query().Where(user.EmailEQ(email)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrEmailTaken
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// First user ever → admin
	count, err := a.client.User.Query().Count(ctx)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		now := time.Now()
		return a.client.User.Create().
			SetEmail(email).
			SetName(name).
			SetPasswordHash(string(hash)).
			SetConfirmed(true).
			SetRole(user.RoleAdmin).
			SetLastLoginAt(now).
			Save(ctx)
	}

	// Check for pending invite
	inv, err := a.client.Invite.Query().
		Where(
			invite.EmailEQ(email),
			invite.AcceptedAtIsNil(),
			invite.ExpiresAtGT(time.Now()),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotAllowed
		}
		return nil, err
	}

	// Create user from invite
	now := time.Now()
	confirmed := !a.config.RequireConfirm
	u, err := a.client.User.Create().
		SetEmail(email).
		SetName(name).
		SetPasswordHash(string(hash)).
		SetConfirmed(confirmed).
		SetRole(user.Role(inv.Role.String())).
		SetLastLoginAt(now).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	a.client.Invite.UpdateOne(inv).SetAcceptedAt(now).Exec(ctx)
	return u, nil
}

// Login authenticates a user with email+password.
func (a *Auth) Login(ctx context.Context, email, password string) (*ent.User, error) {
	u, err := a.client.User.Query().Where(user.EmailEQ(email)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if u.PasswordHash == nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*u.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	now := time.Now()
	a.client.User.UpdateOne(u).SetLastLoginAt(now).Exec(ctx)
	u.LastLoginAt = &now
	return u, nil
}

// --- OIDC ---

// OIDCAuthURL returns the OIDC authorization URL with a state parameter.
func (a *Auth) OIDCAuthURL(state string) string {
	return a.oauth.AuthCodeURL(state)
}

// OIDCClaims extracted from the OIDC ID token.
type OIDCClaims struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// OIDCExchange exchanges an authorization code for tokens and returns the claims.
func (a *Auth) OIDCExchange(ctx context.Context, code string) (*OIDCClaims, error) {
	token, err := a.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}

	var claims OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return &claims, nil
}

// OIDCResolveUser finds or creates a user based on OIDC claims.
// Returns nil if the email is not allowed (no existing user, no invite).
func (a *Auth) OIDCResolveUser(ctx context.Context, claims *OIDCClaims) (*ent.User, error) {
	// Existing user
	u, err := a.client.User.Query().Where(user.EmailEQ(claims.Email)).Only(ctx)
	if err == nil {
		now := time.Now()
		a.client.User.UpdateOne(u).SetLastLoginAt(now).Exec(ctx)
		u.LastLoginAt = &now
		return u, nil
	}
	if !ent.IsNotFound(err) {
		return nil, err
	}

	// First user ever → admin
	count, err := a.client.User.Query().Count(ctx)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		now := time.Now()
		return a.client.User.Create().
			SetEmail(claims.Email).
			SetName(claims.Name).
			SetConfirmed(true).
			SetRole(user.RoleAdmin).
			SetLastLoginAt(now).
			Save(ctx)
	}

	// Pending invite
	inv, err := a.client.Invite.Query().
		Where(
			invite.EmailEQ(claims.Email),
			invite.AcceptedAtIsNil(),
			invite.ExpiresAtGT(time.Now()),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	now := time.Now()
	u, err = a.client.User.Create().
		SetEmail(claims.Email).
		SetName(claims.Name).
		SetConfirmed(true).
		SetRole(user.Role(inv.Role.String())).
		SetLastLoginAt(now).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	a.client.Invite.UpdateOne(inv).SetAcceptedAt(now).Exec(ctx)
	return u, nil
}

// --- Invites ---

// CreateInvite creates a new invite and returns the raw token.
func (a *Auth) CreateInvite(ctx context.Context, inviter *ent.User, email string, role user.Role) (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", err
	}

	hash := hashToken(token)
	_, err = a.client.Invite.Create().
		SetEmail(email).
		SetTokenHash(hash).
		SetRole(invite.Role(role)).
		SetExpiresAt(time.Now().Add(72 * time.Hour)).
		SetInvitedBy(inviter).
		Save(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create invite: %w", err)
	}

	return token, nil
}

// ValidateInviteToken looks up a pending invite by raw token.
func (a *Auth) ValidateInviteToken(ctx context.Context, token string) (*ent.Invite, error) {
	hash := hashToken(token)
	return a.client.Invite.Query().
		Where(
			invite.TokenHashEQ(hash),
			invite.AcceptedAtIsNil(),
			invite.ExpiresAtGT(time.Now()),
		).
		Only(ctx)
}

// --- Sessions ---

// CreateSession creates a new session for a user and returns the raw token.
func (a *Auth) CreateSession(ctx context.Context, u *ent.User) (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", err
	}

	hash := hashToken(token)
	_, err = a.client.Session.Create().
		SetTokenHash(hash).
		SetExpiresAt(time.Now().Add(a.config.SessionMaxAge)).
		SetUser(u).
		Save(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	return token, nil
}

// ValidateSession looks up a session by raw token and returns the associated user.
func (a *Auth) ValidateSession(ctx context.Context, token string) (*ent.User, error) {
	hash := hashToken(token)

	sess, err := a.client.Session.Query().
		Where(
			session.TokenHashEQ(hash),
			session.ExpiresAtGT(time.Now()),
		).
		WithUser().
		Only(ctx)
	if err != nil {
		return nil, err
	}

	return sess.Edges.User, nil
}

// DeleteSession removes a session by raw token.
func (a *Auth) DeleteSession(ctx context.Context, token string) error {
	hash := hashToken(token)
	_, err := a.client.Session.Delete().
		Where(session.TokenHashEQ(hash)).
		Exec(ctx)
	return err
}

// GenerateState creates a random state string for OIDC flows.
func GenerateState() (string, error) {
	return generateToken()
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
