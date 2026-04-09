package server

import (
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"perimeter/ent"
	"perimeter/ent/importerconfig"
	"perimeter/ent/notifierconfig"
	"perimeter/ent/tag"
	"perimeter/ent/user"
	"perimeter/internal/auth"
	"perimeter/internal/importer"
	"perimeter/internal/notifier"
	"perimeter/internal/storage"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

type Server struct {
	app              *fiber.App
	storage          storage.Storage
	auth             *auth.Auth
	client           *ent.Client
	registry         *importer.Registry
	notifierRegistry *notifier.Registry
}

func New(s storage.Storage, a *auth.Auth, client *ent.Client, registry *importer.Registry, notifierReg *notifier.Registry, viewsFS fs.FS) *Server {
	engine := html.NewFileSystem(http.FS(viewsFS), ".html")
	engine.AddFunc("hasTag", func(tags []*ent.Tag, id int) bool {
		for _, t := range tags {
			if t.ID == id {
				return true
			}
		}
		return false
	})

	app := fiber.New(fiber.Config{
		Views: engine,
	})

	srv := &Server{
		app:              app,
		storage:          s,
		auth:             a,
		client:           client,
		registry:         registry,
		notifierRegistry: notifierReg,
	}

	srv.setupRoutes()
	return srv
}

func (s *Server) Listen(addr string) error {
	return s.app.Listen(addr)
}

func (s *Server) setupRoutes() {
	// Public routes
	s.app.Get("/setup", s.handleSetupPage)
	s.app.Post("/setup", s.handleSetup)
	s.app.Get("/login", s.handleLoginPage)
	s.app.Post("/login", s.handleLogin)
	s.app.Get("/register/:token", s.handleRegisterPage)
	s.app.Post("/register", s.handleRegister)
	s.app.Post("/logout", s.handleLogout)

	if s.auth.OIDCEnabled() {
		s.app.Get("/auth/oidc", s.handleOIDCLogin)
		s.app.Get("/auth/callback", s.handleOIDCCallback)
	}

	// Authenticated routes
	authed := s.app.Group("", auth.RequireAuth(s.auth))
	authed.Get("/", s.handleIndex)
	authed.Get("/targets/:id", s.handleTargetDetails)
	authed.Get("/import", s.handleImport)
	authed.Post("/import", s.handleImportSubmit)
	authed.Post("/targets/:id/delete", s.handleDeleteTarget)
	authed.Post("/targets/:id/tags", s.handleUpdateTargetTags)

	// Admin routes
	admin := authed.Group("", auth.RequireRole(user.RoleAdmin))
	admin.Get("/settings", s.handleSettings)
	admin.Post("/invite", s.handleInvite)
	admin.Get("/users", s.handleUsers)
	admin.Post("/users/:id/delete", s.handleDeleteUser)
	admin.Post("/importers", s.handleCreateImporter)
	admin.Post("/importers/:id/delete", s.handleDeleteImporter)
	admin.Post("/importers/:id/toggle", s.handleToggleImporter)
	admin.Post("/notifiers", s.handleCreateNotifier)
	admin.Post("/notifiers/:id/delete", s.handleDeleteNotifier)
	admin.Post("/notifiers/:id/toggle", s.handleToggleNotifier)
	admin.Post("/tags", s.handleCreateTag)
	admin.Post("/tags/:id/delete", s.handleDeleteTag)
}

// templateData returns a fiber.Map with common template data (user, role).
func (s *Server) templateData(c *fiber.Ctx, extra fiber.Map) fiber.Map {
	data := fiber.Map{}
	if u := auth.GetUser(c); u != nil {
		data["User"] = u
		data["IsAdmin"] = u.Role == user.RoleAdmin
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

// --- Auth handlers ---

func (s *Server) handleSetupPage(c *fiber.Ctx) error {
	hasUsers, _ := s.auth.HasUsers(c.Context())
	if hasUsers {
		return c.Redirect("/login")
	}
	return c.Render("views/setup", fiber.Map{}, "views/layouts/main")
}

func (s *Server) handleSetup(c *fiber.Ctx) error {
	hasUsers, _ := s.auth.HasUsers(c.Context())
	if hasUsers {
		return c.Redirect("/login")
	}

	name := c.FormValue("name")
	email := c.FormValue("email")
	password := c.FormValue("password")

	u, err := s.auth.Register(c.Context(), email, name, password)
	if err != nil {
		return c.Render("views/setup", fiber.Map{
			"Error": "Failed to create admin: " + err.Error(),
		}, "views/layouts/main")
	}

	return s.createSessionAndRedirect(c, u)
}

func (s *Server) handleLoginPage(c *fiber.Ctx) error {
	hasUsers, _ := s.auth.HasUsers(c.Context())
	if !hasUsers {
		return c.Redirect("/setup")
	}
	return c.Render("views/login", fiber.Map{
		"OIDCEnabled": s.auth.OIDCEnabled(),
	}, "views/layouts/main")
}

func (s *Server) handleLogin(c *fiber.Ctx) error {
	email := c.FormValue("email")
	password := c.FormValue("password")

	u, err := s.auth.Login(c.Context(), email, password)
	if err != nil {
		return c.Render("views/login", fiber.Map{
			"Error":       "Invalid email or password",
			"OIDCEnabled": s.auth.OIDCEnabled(),
		}, "views/layouts/main")
	}

	return s.createSessionAndRedirect(c, u)
}

func (s *Server) handleRegisterPage(c *fiber.Ctx) error {
	token := c.Params("token")
	// Validate invite token and get email
	inv, err := s.auth.ValidateInviteToken(c.Context(), token)
	if err != nil {
		return c.Status(400).SendString("Invalid or expired invite link")
	}

	return c.Render("views/register", fiber.Map{
		"InviteEmail": inv.Email,
		"InviteToken": token,
	}, "views/layouts/main")
}

func (s *Server) handleRegister(c *fiber.Ctx) error {
	name := c.FormValue("name")
	email := c.FormValue("email")
	password := c.FormValue("password")

	u, err := s.auth.Register(c.Context(), email, name, password)
	if err != nil {
		errMsg := "Registration failed"
		if err == auth.ErrNotAllowed {
			errMsg = "Registration is invite-only"
		} else if err == auth.ErrEmailTaken {
			errMsg = "Email already registered"
		}
		return c.Render("views/register", fiber.Map{
			"Error": errMsg,
		}, "views/layouts/main")
	}

	return s.createSessionAndRedirect(c, u)
}

func (s *Server) handleLogout(c *fiber.Ctx) error {
	token := c.Cookies(auth.SessionCookie)
	if token != "" {
		s.auth.DeleteSession(c.Context(), token)
	}
	c.ClearCookie(auth.SessionCookie)
	return c.Redirect("/login")
}

func (s *Server) handleOIDCLogin(c *fiber.Ctx) error {
	state, _ := auth.GenerateState()
	c.Cookie(&fiber.Cookie{
		Name:     "oidc_state",
		Value:    state,
		HTTPOnly: true,
		MaxAge:   300,
	})
	return c.Redirect(s.auth.OIDCAuthURL(state))
}

func (s *Server) handleOIDCCallback(c *fiber.Ctx) error {
	state := c.Cookies("oidc_state")
	if state == "" || state != c.Query("state") {
		return c.Status(400).SendString("Invalid state")
	}
	c.ClearCookie("oidc_state")

	claims, err := s.auth.OIDCExchange(c.Context(), c.Query("code"))
	if err != nil {
		return c.Status(400).SendString("Authentication failed")
	}

	u, err := s.auth.OIDCResolveUser(c.Context(), claims)
	if err != nil {
		return c.Status(500).SendString("Internal error")
	}
	if u == nil {
		return c.Status(403).SendString("Access denied — no account or invite found for this email")
	}

	return s.createSessionAndRedirect(c, u)
}

func (s *Server) createSessionAndRedirect(c *fiber.Ctx, u *ent.User) error {
	token, err := s.auth.CreateSession(c.Context(), u)
	if err != nil {
		return c.Status(500).SendString("Failed to create session")
	}

	c.Cookie(&fiber.Cookie{
		Name:     auth.SessionCookie,
		Value:    token,
		HTTPOnly: true,
		Path:     "/",
		MaxAge:   30 * 24 * 60 * 60, // 30 days
	})

	return c.Redirect("/")
}

// --- Existing handlers (now with user context) ---

func (s *Server) handleIndex(c *fiber.Ctx) error {
	targets, err := s.storage.GetTargets(c.Context())
	if err != nil {
		return c.Status(500).SendString(err.Error())
	}

	allTags, _ := s.client.Tag.Query().All(c.Context())

	// Filter by tag if specified
	filterTag := c.Query("tag")
	if filterTag != "" {
		var filtered []*ent.Target
		for _, t := range targets {
			for _, tg := range t.Edges.Tags {
				if tg.Name == filterTag {
					filtered = append(filtered, t)
					break
				}
			}
		}
		targets = filtered
	}

	// Compute dashboard stats
	totalTargets := len(targets)
	totalOpenPorts := 0
	expiringCerts := 0
	cspIssues := 0

	for _, t := range targets {
		for _, ip := range t.Edges.Ips {
			if len(ip.Edges.Scans) > 0 {
				latestScan := ip.Edges.Scans[0]
				totalOpenPorts += len(latestScan.Edges.Ports)
			}
		}
		if len(t.Edges.SslScans) > 0 {
			latest := t.Edges.SslScans[0]
			if !latest.CertExpiry.IsZero() && time.Until(latest.CertExpiry) < 30*24*time.Hour {
				expiringCerts++
			}
		}
		if len(t.Edges.CspScans) > 0 {
			latest := t.Edges.CspScans[0]
			if len(latest.Findings) > 0 {
				cspIssues++
			}
		}
	}

	return c.Render("views/index", s.templateData(c, fiber.Map{
		"Title":          "Perimeter Dashboard",
		"Targets":        targets,
		"Tags":           allTags,
		"FilterTag":      filterTag,
		"TotalTargets":   totalTargets,
		"TotalOpenPorts": totalOpenPorts,
		"ExpiringCerts":  expiringCerts,
		"CSPIssues":      cspIssues,
	}), "views/layouts/main")
}

func (s *Server) handleTargetDetails(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return c.Status(400).SendString("Invalid ID")
	}

	target, err := s.storage.GetTarget(c.Context(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			return c.Status(404).SendString("Target not found")
		}
		return c.Status(500).SendString(err.Error())
	}

	allTags, _ := s.client.Tag.Query().All(c.Context())

	return c.Render("views/target", s.templateData(c, fiber.Map{
		"Title":   "Target Details",
		"Target":  target,
		"AllTags": allTags,
	}), "views/layouts/main")
}

func (s *Server) handleDeleteTarget(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return c.Status(400).SendString("Invalid ID")
	}

	err = s.storage.DeleteTarget(c.Context(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			return c.Status(404).SendString("Target not found")
		}
		return c.Status(500).SendString(err.Error())
	}

	return c.Redirect("/")
}

func (s *Server) handleImport(c *fiber.Ctx) error {
	return c.Render("views/import", s.templateData(c, fiber.Map{
		"Title": "Import Targets",
	}), "views/layouts/main")
}

func (s *Server) handleImportSubmit(c *fiber.Ctx) error {
	sourceType := c.FormValue("source")

	var src importer.Source

	switch sourceType {
	case "manual":
		input := c.FormValue("manual_input")
		src = &importer.ManualSource{Input: input}
	default:
		return c.Status(400).SendString("Invalid source type")
	}

	targets, err := src.Fetch(c.Context())
	if err != nil {
		return c.Status(500).SendString(err.Error())
	}

	_, err = s.storage.ImportTargets(c.Context(), targets)
	if err != nil {
		return c.Status(500).SendString(err.Error())
	}

	return c.Redirect("/")
}

// --- Admin handlers ---

func (s *Server) settingsData(c *fiber.Ctx, extra fiber.Map) fiber.Map {
	users, _ := s.client.User.Query().All(c.Context())
	importers, _ := s.client.ImporterConfig.Query().All(c.Context())
	notifiers, _ := s.client.NotifierConfig.Query().All(c.Context())
	tags, _ := s.client.Tag.Query().All(c.Context())
	providers := s.registry.List()
	notifierProviders := s.notifierRegistry.List()

	data := s.templateData(c, fiber.Map{
		"Title":             "Settings",
		"Users":             users,
		"Importers":         importers,
		"Notifiers":         notifiers,
		"Tags":              tags,
		"Providers":         providers,
		"NotifierProviders": notifierProviders,
	})
	for k, v := range extra {
		data[k] = v
	}
	return data
}

func (s *Server) handleSettings(c *fiber.Ctx) error {
	return c.Render("views/settings", s.settingsData(c, nil), "views/layouts/main")
}

func (s *Server) handleInvite(c *fiber.Ctx) error {
	u := auth.GetUser(c)
	email := c.FormValue("email")
	role := c.FormValue("role")

	inviteRole := user.RoleMember
	if role == "admin" {
		inviteRole = user.RoleAdmin
	}

	token, err := s.auth.CreateInvite(c.Context(), u, email, inviteRole)
	if err != nil {
		return c.Render("views/settings", s.settingsData(c, fiber.Map{
			"Error": "Failed to create invite: " + err.Error(),
		}), "views/layouts/main")
	}

	inviteLink := fmt.Sprintf("%s/register/%s", c.BaseURL(), token)

	return c.Render("views/settings", s.settingsData(c, fiber.Map{
		"InviteLink":  inviteLink,
		"InviteEmail": email,
	}), "views/layouts/main")
}

func (s *Server) handleUsers(c *fiber.Ctx) error {
	return c.Redirect("/settings")
}

func (s *Server) handleDeleteUser(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).SendString("Invalid ID")
	}

	// Don't allow deleting yourself
	currentUser := auth.GetUser(c)
	if currentUser.ID == id {
		return c.Render("views/settings", s.settingsData(c, fiber.Map{
			"Error": "Cannot delete your own account",
		}), "views/layouts/main")
	}

	if err := s.client.User.DeleteOneID(id).Exec(c.Context()); err != nil {
		return c.Render("views/settings", s.settingsData(c, fiber.Map{
			"Error": "Failed to delete user: " + err.Error(),
		}), "views/layouts/main")
	}

	return c.Redirect("/settings")
}

func (s *Server) handleCreateImporter(c *fiber.Ctx) error {
	provider := c.FormValue("provider")
	credentials := c.FormValue("credentials")
	intervalStr := c.FormValue("sync_interval")

	interval, err := strconv.ParseInt(intervalStr, 10, 64)
	if err != nil || interval < 60 {
		interval = 3600 // Default 1 hour
	}

	_, err = s.client.ImporterConfig.Create().
		SetProvider(importerconfig.Provider(provider)).
		SetCredentials([]byte(credentials)).
		SetSyncIntervalSeconds(interval).
		SetEnabled(true).
		Save(c.Context())
	if err != nil {
		return c.Render("views/settings", s.settingsData(c, fiber.Map{
			"Error": "Failed to create importer: " + err.Error(),
		}), "views/layouts/main")
	}

	return c.Redirect("/settings")
}

func (s *Server) handleDeleteImporter(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).SendString("Invalid ID")
	}

	if err := s.client.ImporterConfig.DeleteOneID(id).Exec(c.Context()); err != nil {
		return c.Render("views/settings", s.settingsData(c, fiber.Map{
			"Error": "Failed to delete importer: " + err.Error(),
		}), "views/layouts/main")
	}

	return c.Redirect("/settings")
}

func (s *Server) handleToggleImporter(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).SendString("Invalid ID")
	}

	cfg, err := s.client.ImporterConfig.Get(c.Context(), id)
	if err != nil {
		return c.Status(404).SendString("Importer not found")
	}

	s.client.ImporterConfig.UpdateOne(cfg).SetEnabled(!cfg.Enabled).Exec(c.Context())
	return c.Redirect("/settings")
}

// --- Notifier handlers ---

func (s *Server) handleCreateNotifier(c *fiber.Ctx) error {
	provider := c.FormValue("provider")
	config := c.FormValue("config")

	_, err := s.client.NotifierConfig.Create().
		SetProvider(notifierconfig.Provider(provider)).
		SetConfig([]byte(config)).
		SetEnabled(true).
		Save(c.Context())
	if err != nil {
		return c.Render("views/settings", s.settingsData(c, fiber.Map{
			"Error": "Failed to create notifier: " + err.Error(),
		}), "views/layouts/main")
	}

	return c.Redirect("/settings")
}

func (s *Server) handleDeleteNotifier(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).SendString("Invalid ID")
	}

	if err := s.client.NotifierConfig.DeleteOneID(id).Exec(c.Context()); err != nil {
		return c.Render("views/settings", s.settingsData(c, fiber.Map{
			"Error": "Failed to delete notifier: " + err.Error(),
		}), "views/layouts/main")
	}

	return c.Redirect("/settings")
}

func (s *Server) handleToggleNotifier(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).SendString("Invalid ID")
	}

	cfg, err := s.client.NotifierConfig.Get(c.Context(), id)
	if err != nil {
		return c.Status(404).SendString("Notifier not found")
	}

	s.client.NotifierConfig.UpdateOne(cfg).SetEnabled(!cfg.Enabled).Exec(c.Context())
	return c.Redirect("/settings")
}

// --- Tag handlers ---

func (s *Server) handleCreateTag(c *fiber.Ctx) error {
	name := c.FormValue("name")
	color := c.FormValue("color")
	if color == "" {
		color = "#6b7280"
	}

	_, err := s.client.Tag.Create().
		SetName(name).
		SetColor(color).
		Save(c.Context())
	if err != nil {
		return c.Render("views/settings", s.settingsData(c, fiber.Map{
			"Error": "Failed to create tag: " + err.Error(),
		}), "views/layouts/main")
	}

	return c.Redirect("/settings")
}

func (s *Server) handleDeleteTag(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).SendString("Invalid ID")
	}

	if err := s.client.Tag.DeleteOneID(id).Exec(c.Context()); err != nil {
		return c.Render("views/settings", s.settingsData(c, fiber.Map{
			"Error": "Failed to delete tag: " + err.Error(),
		}), "views/layouts/main")
	}

	return c.Redirect("/settings")
}

func (s *Server) handleUpdateTargetTags(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).SendString("Invalid ID")
	}

	t, err := s.client.Target.Get(c.Context(), id)
	if err != nil {
		return c.Status(404).SendString("Target not found")
	}

	// Get selected tag IDs from form
	tagIDs := c.Context().PostArgs().PeekMulti("tags")
	var ids []int
	for _, raw := range tagIDs {
		if tid, err := strconv.Atoi(string(raw)); err == nil {
			ids = append(ids, tid)
		}
	}

	// Clear existing tags and set new ones
	s.client.Target.UpdateOne(t).ClearTags().Exec(c.Context())
	if len(ids) > 0 {
		tags, _ := s.client.Tag.Query().Where(tag.IDIn(ids...)).All(c.Context())
		s.client.Target.UpdateOne(t).AddTags(tags...).Exec(c.Context())
	}

	return c.Redirect(fmt.Sprintf("/targets/%d", id))
}
