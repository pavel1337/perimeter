package server

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"perimeter/ent"
	"perimeter/ent/importerconfig"
	"perimeter/ent/notifierconfig"
	"perimeter/ent/tag"
	"perimeter/ent/target"
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
	// certExpiryWindow is how close to expiry a certificate has to be before
	// the dashboard calls it out.
	certExpiryWindow time.Duration
}

func New(s storage.Storage, a *auth.Auth, client *ent.Client, registry *importer.Registry, notifierReg *notifier.Registry, viewsFS fs.FS, certExpiryWindow time.Duration) *Server {
	engine := html.NewFileSystem(http.FS(viewsFS), ".html")
	// Whole days until a certificate expires; negative once it has.
	engine.AddFunc("daysUntil", func(t time.Time) int {
		return int(time.Until(t).Hours() / 24)
	})
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
		certExpiryWindow: certExpiryWindow,
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
	authed.Get("/targets/:id/export", s.handleExportTarget)

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
		switch err {
		case auth.ErrNotAllowed:
			errMsg = "Registration is invite-only"
		case auth.ErrEmailTaken:
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
		if err := s.auth.DeleteSession(c.Context(), token); err != nil {
			log.Printf("Logout: failed to delete session: %v", err)
		}
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

// reachabilityStates is the dashboard's state filter, in display order.
var reachabilityStates = []target.Reachability{
	target.ReachabilityOk,
	target.ReachabilityUnreachable,
	target.ReachabilityUnresolved,
	target.ReachabilityPending,
}

func (s *Server) handleIndex(c *fiber.Ctx) error {
	filterState := c.Query("state")
	var states []target.Reachability
	if filterState != "" {
		st := target.Reachability(filterState)
		if target.ReachabilityValidator(st) != nil {
			return c.Status(400).SendString("Invalid state")
		}
		states = append(states, st)
	}

	targets, err := s.storage.GetTargets(c.Context(), states...)
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
			untilExpiry := time.Until(latest.CertExpiry)
			if !latest.CertExpiry.IsZero() && untilExpiry > 0 && untilExpiry < s.certExpiryWindow {
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
		"FilterState":    filterState,
		"States":         reachabilityStates,
		"TotalTargets":   totalTargets,
		"TotalOpenPorts": totalOpenPorts,
		"ExpiringCerts":  expiringCerts,
		"CSPIssues":      cspIssues,
		// Days, so the template can compare it against daysUntil.
		"CertExpiryDays": int(s.certExpiryWindow.Hours() / 24),
	}), "views/layouts/main")
}

const scanPageSize = 10

type pagination struct {
	Page       int
	TotalPages int
	PrevURL    string
	NextURL    string
}

// portScanView decorates a stored scan with the change that started it, so the
// history reads as a change log rather than a list of samples.
type portScanView struct {
	*ent.PortScan
	Added   []int
	Removed []int
}

type ipScanRow struct {
	IP         *ent.IP
	Scans      []portScanView
	Pagination pagination
}

func ipPageKey(ipID int) string { return fmt.Sprintf("ip_%d_page", ipID) }

func parsePage(c *fiber.Ctx, key string) int {
	p, err := strconv.Atoi(c.Query(key, "1"))
	if err != nil || p < 1 {
		return 1
	}
	return p
}

func buildPageLink(c *fiber.Ctx, key string, page int) string {
	v := url.Values{}
	v.Set(key, strconv.Itoa(page))
	return c.Path() + "?" + v.Encode()
}

func clampPage(page, total int) int {
	totalPages := (total + scanPageSize - 1) / scanPageSize
	if totalPages < 1 {
		return 1
	}
	if page > totalPages {
		return totalPages
	}
	return page
}

func buildPagination(c *fiber.Ctx, key string, page, total int) pagination {
	totalPages := (total + scanPageSize - 1) / scanPageSize
	if totalPages < 1 {
		totalPages = 1
	}

	p := pagination{Page: page, TotalPages: totalPages}
	if page > 1 {
		p.PrevURL = buildPageLink(c, key, page-1)
	}
	if page < totalPages {
		p.NextURL = buildPageLink(c, key, page+1)
	}
	return p
}

func (s *Server) sslHistoryData(ctx context.Context, c *fiber.Ctx, targetID int) ([]*ent.SSLScan, pagination, error) {
	page := parsePage(c, "ssl_page")
	items, total, err := s.storage.GetSSLScansPage(ctx, targetID, scanPageSize, (page-1)*scanPageSize)
	if err != nil {
		return nil, pagination{}, err
	}
	if settled := clampPage(page, total); settled != page {
		items, _, err = s.storage.GetSSLScansPage(ctx, targetID, scanPageSize, (settled-1)*scanPageSize)
		if err != nil {
			return nil, pagination{}, err
		}
		page = settled
	}
	return items, buildPagination(c, "ssl_page", page, total), nil
}

func (s *Server) cspHistoryData(ctx context.Context, c *fiber.Ctx, targetID int) ([]*ent.CSPScan, pagination, error) {
	page := parsePage(c, "csp_page")
	items, total, err := s.storage.GetCSPScansPage(ctx, targetID, scanPageSize, (page-1)*scanPageSize)
	if err != nil {
		return nil, pagination{}, err
	}
	if settled := clampPage(page, total); settled != page {
		items, _, err = s.storage.GetCSPScansPage(ctx, targetID, scanPageSize, (settled-1)*scanPageSize)
		if err != nil {
			return nil, pagination{}, err
		}
		page = settled
	}
	return items, buildPagination(c, "csp_page", page, total), nil
}

func (s *Server) ipHistoryData(ctx context.Context, c *fiber.Ctx, i *ent.IP) (ipScanRow, error) {
	page := parsePage(c, ipPageKey(i.ID))
	// One row past the page so the oldest row on it can still be diffed.
	items, total, err := s.storage.GetIPScansPage(ctx, i.ID, scanPageSize+1, (page-1)*scanPageSize)
	if err != nil {
		return ipScanRow{}, err
	}
	if settled := clampPage(page, total); settled != page {
		items, _, err = s.storage.GetIPScansPage(ctx, i.ID, scanPageSize+1, (settled-1)*scanPageSize)
		if err != nil {
			return ipScanRow{}, err
		}
		page = settled
	}
	return ipScanRow{IP: i, Scans: diffPortScans(items), Pagination: buildPagination(c, ipPageKey(i.ID), page, total)}, nil
}

// diffPortScans annotates each row with the ports gained and lost relative to
// the row before it. Rows arrive newest first; the trailing lookahead row is
// dropped after it has been used as a baseline.
func diffPortScans(items []*ent.PortScan) []portScanView {
	views := make([]portScanView, 0, len(items))
	for n, scan := range items {
		v := portScanView{PortScan: scan}
		if n+1 < len(items) {
			v.Added, v.Removed = portDelta(scanPorts(items[n+1]), scanPorts(scan))
		}
		views = append(views, v)
	}
	if len(views) > scanPageSize {
		views = views[:scanPageSize]
	}
	return views
}

func scanPorts(scan *ent.PortScan) []int {
	numbers := make([]int, 0, len(scan.Edges.Ports))
	for _, p := range scan.Edges.Ports {
		numbers = append(numbers, p.Number)
	}
	return numbers
}

// portDelta returns the ports in curr but not prev, and the reverse.
func portDelta(prev, curr []int) (added, removed []int) {
	was := make(map[int]bool, len(prev))
	for _, p := range prev {
		was[p] = true
	}
	now := make(map[int]bool, len(curr))
	for _, p := range curr {
		now[p] = true
		if !was[p] {
			added = append(added, p)
		}
	}
	for _, p := range prev {
		if !now[p] {
			removed = append(removed, p)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}

func (s *Server) handleTargetDetails(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return c.Status(400).SendString("Invalid ID")
	}

	target, err := s.storage.GetTargetBasic(c.Context(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			return c.Status(404).SendString("Target not found")
		}
		return c.Status(500).SendString(err.Error())
	}

	switch c.Query("fragment") {
	case "ssl":
		sslScans, sslPagination, err := s.sslHistoryData(c.Context(), c, target.ID)
		if err != nil {
			return c.Status(500).SendString(err.Error())
		}
		return c.Render("views/partials/ssl_section", fiber.Map{
			"SSLScans":      sslScans,
			"SSLPagination": sslPagination,
		})
	case "csp":
		cspScans, cspPagination, err := s.cspHistoryData(c.Context(), c, target.ID)
		if err != nil {
			return c.Status(500).SendString(err.Error())
		}
		return c.Render("views/partials/csp_section", fiber.Map{
			"CSPScans":      cspScans,
			"CSPPagination": cspPagination,
		})
	case "ip":
		ipID, err := strconv.Atoi(c.Query("ipId"))
		if err != nil {
			return c.Status(400).SendString("Invalid ipId")
		}
		for _, i := range target.Edges.Ips {
			if i.ID == ipID {
				row, err := s.ipHistoryData(c.Context(), c, i)
				if err != nil {
					return c.Status(500).SendString(err.Error())
				}
				return c.Render("views/partials/ip_section", row)
			}
		}
		return c.Status(404).SendString("IP not found")
	}

	sslScans, sslPagination, err := s.sslHistoryData(c.Context(), c, target.ID)
	if err != nil {
		return c.Status(500).SendString(err.Error())
	}
	cspScans, cspPagination, err := s.cspHistoryData(c.Context(), c, target.ID)
	if err != nil {
		return c.Status(500).SendString(err.Error())
	}
	ipRows := make([]ipScanRow, 0, len(target.Edges.Ips))
	for _, i := range target.Edges.Ips {
		row, err := s.ipHistoryData(c.Context(), c, i)
		if err != nil {
			return c.Status(500).SendString(err.Error())
		}
		ipRows = append(ipRows, row)
	}

	allTags, _ := s.client.Tag.Query().All(c.Context())

	return c.Render("views/target", s.templateData(c, fiber.Map{
		"Title":         "Target Details",
		"Target":        target,
		"AllTags":       allTags,
		"IPRows":        ipRows,
		"SSLScans":      sslScans,
		"SSLPagination": sslPagination,
		"CSPScans":      cspScans,
		"CSPPagination": cspPagination,
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

	// Validate credentials now instead of silently failing in the background sync loop.
	if _, err := s.registry.Get(provider, []byte(credentials)); err != nil {
		return c.Render("views/settings", s.settingsData(c, fiber.Map{
			"Error": "Invalid importer config: " + err.Error(),
		}), "views/layouts/main")
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

	if err := s.client.ImporterConfig.UpdateOne(cfg).SetEnabled(!cfg.Enabled).Exec(c.Context()); err != nil {
		return c.Status(500).SendString("Failed to toggle importer")
	}
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

	if err := s.client.NotifierConfig.UpdateOne(cfg).SetEnabled(!cfg.Enabled).Exec(c.Context()); err != nil {
		return c.Status(500).SendString("Failed to toggle notifier")
	}
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
	if err := s.client.Target.UpdateOne(t).ClearTags().Exec(c.Context()); err != nil {
		return c.Status(500).SendString("Failed to clear tags")
	}
	if len(ids) > 0 {
		tags, _ := s.client.Tag.Query().Where(tag.IDIn(ids...)).All(c.Context())
		if err := s.client.Target.UpdateOne(t).AddTags(tags...).Exec(c.Context()); err != nil {
			return c.Status(500).SendString("Failed to set tags")
		}
	}

	return c.Redirect(fmt.Sprintf("/targets/%d", id))
}

// --- Export handler ---

type exportData struct {
	Target       string      `json:"target"`
	IsIP         bool        `json:"is_ip"`
	Reachability string      `json:"reachability"`
	IPs          []exportIP  `json:"ips,omitempty"`
	SSL          []exportSSL `json:"ssl_scans,omitempty"`
	CSP          []exportCSP `json:"csp_scans,omitempty"`
}

type exportIP struct {
	Address string           `json:"address"`
	Scans   []exportPortScan `json:"scans,omitempty"`
}

type exportPortScan struct {
	ScannedAt string `json:"scanned_at"`
	Ports     []int  `json:"ports"`
}

type exportSSL struct {
	ScannedAt       string   `json:"scanned_at"`
	Grade           string   `json:"grade"`
	Status          string   `json:"status"`
	CertSubject     string   `json:"cert_subject,omitempty"`
	CertIssuer      string   `json:"cert_issuer,omitempty"`
	CertExpiry      string   `json:"cert_expiry,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
}

type exportCSP struct {
	ScannedAt  string `json:"scanned_at"`
	Header     string `json:"csp_header"`
	Findings   int    `json:"findings_count"`
	ProbeError string `json:"probe_error,omitempty"`
}

func (s *Server) handleExportTarget(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).SendString("Invalid ID")
	}

	t, err := s.storage.GetTarget(c.Context(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			return c.Status(404).SendString("Target not found")
		}
		return c.Status(500).SendString(err.Error())
	}

	format := c.Query("format", "json")

	data := exportData{
		Target:       t.Input,
		IsIP:         t.IsIP,
		Reachability: string(t.Reachability),
	}

	for _, ip := range t.Edges.Ips {
		eip := exportIP{Address: ip.Address}
		for _, scan := range ip.Edges.Scans {
			var ports []int
			for _, p := range scan.Edges.Ports {
				ports = append(ports, p.Number)
			}
			eip.Scans = append(eip.Scans, exportPortScan{
				ScannedAt: scan.ScannedAt.Format(time.RFC3339),
				Ports:     ports,
			})
		}
		data.IPs = append(data.IPs, eip)
	}

	for _, scan := range t.Edges.SslScans {
		essl := exportSSL{
			ScannedAt:       scan.ScannedAt.Format(time.RFC3339),
			Grade:           scan.Grade,
			Status:          scan.Status,
			CertSubject:     scan.CertSubject,
			CertIssuer:      scan.CertIssuer,
			Vulnerabilities: scan.Vulnerabilities,
		}
		if !scan.CertExpiry.IsZero() {
			essl.CertExpiry = scan.CertExpiry.Format("2006-01-02")
		}
		data.SSL = append(data.SSL, essl)
	}

	for _, scan := range t.Edges.CspScans {
		data.CSP = append(data.CSP, exportCSP{
			ScannedAt:  scan.ScannedAt.Format(time.RFC3339),
			Header:     scan.CspHeader,
			Findings:   len(scan.Findings),
			ProbeError: scan.ProbeError,
		})
	}

	switch format {
	case "csv":
		c.Set("Content-Type", "text/csv")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", t.Input))

		rows := [][]string{{"type", "timestamp", "detail", "value"}}
		for _, ip := range data.IPs {
			for _, scan := range ip.Scans {
				portStrs := make([]string, len(scan.Ports))
				for i, p := range scan.Ports {
					portStrs[i] = strconv.Itoa(p)
				}
				rows = append(rows, []string{"port_scan", scan.ScannedAt, ip.Address, strings.Join(portStrs, ";")})
			}
		}
		for _, scan := range data.SSL {
			rows = append(rows, []string{"ssl_scan", scan.ScannedAt, scan.Grade, scan.Status})
		}
		for _, scan := range data.CSP {
			detail := strconv.Itoa(scan.Findings) + " findings"
			if scan.ProbeError != "" {
				detail = "no HTTP response: " + scan.ProbeError
			}
			rows = append(rows, []string{"csp_scan", scan.ScannedAt, detail, scan.Header})
		}

		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		if err := w.WriteAll(rows); err != nil {
			return c.Status(500).SendString("Failed to write CSV")
		}
		return c.Send(buf.Bytes())

	default:
		c.Set("Content-Type", "application/json")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.json", t.Input))
		out, _ := json.MarshalIndent(data, "", "  ")
		return c.Send(out)
	}
}
