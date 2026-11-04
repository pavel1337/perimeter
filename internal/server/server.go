package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
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
	"perimeter/ent/schema"
	"perimeter/ent/tag"
	"perimeter/ent/target"
	"perimeter/ent/user"
	"perimeter/internal/auth"
	"perimeter/internal/importer"
	"perimeter/internal/notifier"
	"perimeter/internal/service"
	"perimeter/internal/storage"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

// importerSyncer runs one importer sync. main wires the background sync
// loop in; the "Sync now" button calls it.
type importerSyncer interface {
	SyncOne(ctx context.Context, cfg *ent.ImporterConfig) (int, error)
}

type Server struct {
	app              *fiber.App
	storage          storage.Storage
	auth             *auth.Auth
	client           *ent.Client
	registry         *importer.Registry
	notifierRegistry *notifier.Registry
	syncer           importerSyncer
	// certExpiryWindow is how close to expiry a certificate has to be before
	// the dashboard calls it out.
	certExpiryWindow time.Duration
	// dashboardPageSize is how many targets the dashboard shows per page.
	dashboardPageSize int
	// apiLimiter throttles /api/v1 per token. SetAPIRateLimit replaces it.
	apiLimiter fiber.Handler
	// rescanCooldown is how long a target waits between rescan requests.
	rescanCooldown time.Duration
	// sslScanning is whether SSL Labs scanning runs; a rescan only flags SSL
	// when a producer will pick it up.
	sslScanning bool
	// svc is the transport-independent layer that the API, MCP and the
	// audited UI writes share.
	svc *service.Service
}

// defaultRescanCooldown is the default wait between rescan requests of one
// target (RESCAN_COOLDOWN).
const defaultRescanCooldown = 10 * time.Minute

func New(s storage.Storage, a *auth.Auth, client *ent.Client, registry *importer.Registry, notifierReg *notifier.Registry, viewsFS fs.FS, certExpiryWindow time.Duration, dashboardPageSize int) *Server {
	engine := newViewEngine(viewsFS)

	if dashboardPageSize < 1 {
		dashboardPageSize = defaultDashboardPageSize
	}

	srv := &Server{
		storage:           s,
		auth:              a,
		client:            client,
		registry:          registry,
		notifierRegistry:  notifierReg,
		certExpiryWindow:  certExpiryWindow,
		dashboardPageSize: dashboardPageSize,
		rescanCooldown:    defaultRescanCooldown,
		svc:               service.New(s, client, certExpiryWindow),
	}
	srv.svc.SetRescanConfig(defaultRescanCooldown, false)
	srv.SetAPIRateLimit(defaultAPIRateLimit)

	app := fiber.New(fiber.Config{
		Views:        engine,
		ErrorHandler: srv.errorHandler,
	})
	srv.app = app

	srv.setupRoutes()
	return srv
}

// SetImporterSyncer enables the "Sync now" button. The loop is created in
// main, after the server, so it is set here instead of in New.
func (s *Server) SetImporterSyncer(sy importerSyncer) {
	s.syncer = sy
}

// SetRescanCooldown sets how long a target waits between rescan requests.
func (s *Server) SetRescanCooldown(d time.Duration) {
	s.rescanCooldown = d
	s.svc.SetRescanConfig(s.rescanCooldown, s.sslScanning)
}

// SetSSLScanning tells the server whether SSL Labs scanning runs, so that a
// rescan flags SSL only when the SSL producer will act on it.
func (s *Server) SetSSLScanning(enabled bool) {
	s.sslScanning = enabled
	s.svc.SetRescanConfig(s.rescanCooldown, s.sslScanning)
}

// newViewEngine loads the templates from viewsFS and registers the template
// funcs the views use.
func newViewEngine(viewsFS fs.FS) *html.Engine {
	engine := html.NewFileSystem(http.FS(viewsFS), ".html")
	// Whole days until a certificate expires; negative once it has.
	// Takes a pointer so templates can pass the nullable LatestCertExpiry
	// column directly; a nil pointer is reported as 0.
	engine.AddFunc("daysUntil", func(t *time.Time) int {
		if t == nil {
			return 0
		}
		return int(time.Until(*t).Hours() / 24)
	})
	engine.AddFunc("hasTag", func(tags []*ent.Tag, id int) bool {
		for _, t := range tags {
			if t.ID == id {
				return true
			}
		}
		return false
	})

	engine.AddFunc("withQuery", withQuery)
	engine.AddFunc("sslFailed", storage.SSLCheckFailed)
	engine.AddFunc("cspNoApp", func(sc *ent.CSPScan) int {
		code, _ := storage.CSPNoApp(sc)
		return code
	})
	engine.AddFunc("trimPrefix", strings.TrimPrefix)
	engine.AddFunc("hasPrefix", strings.HasPrefix)
	engine.AddFunc("certProblems", storage.CertProblems)
	engine.AddFunc("join", strings.Join)
	engine.AddFunc("dnsChangeSummary", service.DNSChangeSummary)
	engine.AddFunc("eventLabel", notifierEventLabel)
	engine.AddFunc("formValue", formValue)
	engine.AddFunc("formChecked", formChecked)
	engine.AddFunc("tokenStatus", tokenStatus)
	return engine
}

func (s *Server) Listen(addr string) error {
	return s.app.Listen(addr)
}

func (s *Server) setupRoutes() {
	// Security headers on every response, before anything else.
	s.app.Use(securityHeaders())

	// Before every route, public ones included: login and setup forms are
	// CSRF targets too.
	s.app.Use(crossOriginProtection())

	// Bearer-token API. Mounted before the cookie group below, which would
	// otherwise catch these paths first.
	s.setupAPIRoutes()

	// Public routes
	s.app.Get("/setup", s.handleSetupPage)
	s.app.Post("/setup", s.handleSetup)
	s.app.Get("/login", s.handleLoginPage)
	s.app.Post("/login", s.handleLogin)
	s.app.Get("/login/2fa", s.handleLogin2FAPage)
	s.app.Post("/login/2fa", s.handleLogin2FA)
	s.app.Get("/register/:token", s.handleRegisterPage)
	s.app.Post("/register", s.handleRegister)
	s.app.Post("/logout", s.handleLogout)

	if s.auth.OIDCEnabled() {
		s.app.Get("/auth/oidc", s.handleOIDCLogin)
		s.app.Get("/auth/callback", s.handleOIDCCallback)
	}

	// Authenticated routes. Role checks are attached per route, not as a
	// sub-group at "", so an authenticated non-admin on an unknown path
	// gets a 404 instead of a 403.
	authed := s.app.Group("", auth.RequireAuth(s.auth))
	canWrite := auth.RequireRole(user.RoleAdmin, user.RoleMember)
	adminOnly := auth.RequireRole(user.RoleAdmin)
	authed.Get("/", s.handleIndex)
	// Registered before /targets/:id so "deleted" is not read as an id.
	authed.Get("/targets/deleted", s.handleDeletedTargets)
	authed.Get("/targets/:id", s.handleTargetDetails)
	authed.Get("/import", canWrite, s.handleImport)
	authed.Post("/import", canWrite, s.handleImportSubmit)
	// Registered before /targets/:id/... so "bulk" is not read as an id.
	authed.Post("/targets/bulk/export", s.handleBulkExport)
	authed.Post("/targets/bulk/delete", canWrite, s.handleBulkDelete)
	authed.Post("/targets/bulk/rescan", canWrite, s.handleBulkRescan)
	authed.Post("/targets/:id/delete", canWrite, s.handleDeleteTarget)
	authed.Post("/targets/:id/rescan", canWrite, s.handleRescanTarget)
	authed.Post("/targets/:id/restore", canWrite, s.handleRestoreTarget)
	authed.Post("/targets/:id/purge", adminOnly, s.handlePurgeTarget)
	authed.Post("/targets/:id/tags", canWrite, s.handleUpdateTargetTags)
	authed.Get("/targets/:id/export", s.handleExportTarget)

	// Account pages: every role can manage its own two-factor.
	authed.Get("/account", s.handleAccount)
	authed.Post("/account/2fa/setup", s.handleAccountSetup)
	authed.Get("/account/2fa/setup", s.handleAccountSetupPage)
	authed.Post("/account/2fa/confirm", s.handleAccountConfirm)
	authed.Post("/account/2fa/recovery", s.handleAccountRecovery)
	authed.Post("/account/2fa/disable", s.handleAccountDisable)
	authed.Post("/account/tokens", s.handleCreateAPIToken)
	authed.Post("/account/tokens/:id/revoke", s.handleRevokeAPIToken)

	// Admin routes
	authed.Get("/settings", adminOnly, s.handleSettings)
	authed.Get("/settings/audit", adminOnly, s.handleAuditPage)
	authed.Post("/invite", adminOnly, s.handleInvite)
	authed.Get("/users", adminOnly, s.handleUsers)
	authed.Post("/users/:id/delete", adminOnly, s.handleDeleteUser)
	authed.Post("/users/:id/2fa/reset", adminOnly, s.handleResetTOTP)
	authed.Post("/users/:id/role", adminOnly, s.handleChangeRole)
	authed.Post("/importers", adminOnly, s.handleCreateImporter)
	authed.Post("/importers/:id/delete", adminOnly, s.handleDeleteImporter)
	authed.Post("/importers/:id/toggle", adminOnly, s.handleToggleImporter)
	authed.Post("/importers/:id/sync", adminOnly, s.handleSyncImporter)
	authed.Post("/notifiers", adminOnly, s.handleCreateNotifier)
	authed.Post("/notifiers/:id/delete", adminOnly, s.handleDeleteNotifier)
	authed.Post("/notifiers/:id/toggle", adminOnly, s.handleToggleNotifier)
	authed.Post("/tags", adminOnly, s.handleCreateTag)
	authed.Post("/tags/:id/delete", adminOnly, s.handleDeleteTag)
	authed.Post("/settings/tokens/:id/revoke", adminOnly, s.handleAdminRevokeAPIToken)

	// Catch-all: a path no route claimed renders the 404 page instead of
	// fiber's plain text. Registered last, so only unmatched paths reach it.
	s.app.Use(func(c *fiber.Ctx) error { return fiber.ErrNotFound })
}

// templateData returns a fiber.Map with common template data (user, role, and
// the pending flash message).
func (s *Server) templateData(c *fiber.Ctx, extra fiber.Map) fiber.Map {
	data := fiber.Map{}
	if u := auth.GetUser(c); u != nil {
		data["User"] = u
		data["IsAdmin"] = u.Role == user.RoleAdmin
		data["CanWrite"] = u.Role == user.RoleAdmin || u.Role == user.RoleMember
	}
	for k, v := range extra {
		data[k] = v
	}
	// Popped even when extra sets its own Flash, so the cookie is always cleared.
	if f := popFlash(c); f != nil {
		if _, set := data["Flash"]; !set {
			data["Flash"] = f
		}
	}
	return data
}

// errorHandler renders views/error for every error the app raises, so unknown
// URLs and 403s get the same look as the rest of the UI.
func (s *Server) errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	msg := err.Error()
	var fe *fiber.Error
	if errors.As(err, &fe) {
		code, msg = fe.Code, fe.Message
	}
	if code >= 500 {
		// Internal errors are logged, not shown: they can carry SQL or paths.
		log.Printf("%s %s: %v", c.Method(), c.Path(), err)
		msg = "An unexpected error occurred. Check the server log for details."
	}
	// The /api/ and /mcp routes answer in JSON, whatever went wrong.
	if strings.HasPrefix(c.Path(), "/api/") || c.Path() == "/mcp" {
		return apiError(c, code, apiErrorCode(code), msg)
	}
	title := "Something went wrong"
	switch code {
	case fiber.StatusNotFound:
		title = "Page not found"
	case fiber.StatusForbidden:
		title = "Forbidden"
	}
	if err := c.Status(code).Render("views/error", s.templateData(c, fiber.Map{
		"ErrorTitle":   title,
		"ErrorMessage": msg,
	}), "views/layouts/main"); err != nil {
		log.Printf("render error page: %v", err)
		return c.Status(code).SendString(title)
	}
	return nil
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
			"Error": userError("create admin", err),
		}, "views/layouts/main")
	}

	return s.createSessionAndRedirect(c, u)
}

func (s *Server) handleLoginPage(c *fiber.Ctx) error {
	hasUsers, _ := s.auth.HasUsers(c.Context())
	if !hasUsers {
		return c.Redirect("/setup")
	}
	return c.Render("views/login", s.templateData(c, fiber.Map{
		"OIDCEnabled": s.auth.OIDCEnabled(),
	}), "views/layouts/main")
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

	if u.TotpEnabled {
		return s.startSecondFactor(c, u)
	}
	return s.createSessionAndRedirect(c, u)
}

func (s *Server) handleRegisterPage(c *fiber.Ctx) error {
	token := c.Params("token")
	// Validate invite token and get email
	inv, err := s.auth.ValidateInviteToken(c.Context(), token)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid or expired invite link")
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
		// Only over a TLS connection; c.Protocol() honours X-Forwarded-Proto
		// behind a reverse proxy.
		Secure: c.Protocol() == "https",
	})
	return c.Redirect(s.auth.OIDCAuthURL(state))
}

func (s *Server) handleOIDCCallback(c *fiber.Ctx) error {
	state := c.Cookies("oidc_state")
	if state == "" || state != c.Query("state") {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid state")
	}
	c.ClearCookie("oidc_state")

	claims, err := s.auth.OIDCExchange(c.Context(), c.Query("code"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Authentication failed")
	}

	u, err := s.auth.OIDCResolveUser(c.Context(), claims)
	if err != nil {
		return err
	}
	if u == nil {
		return fiber.NewError(fiber.StatusForbidden, "Access denied — no account or invite found for this email")
	}

	// OIDC matches accounts by email, so a password account with two-factor on
	// can also arrive here. It gets the same code prompt as a password login;
	// otherwise signing in through the identity provider would skip its 2FA.
	if u.TotpEnabled {
		return s.startSecondFactor(c, u)
	}
	return s.createSessionAndRedirect(c, u)
}

func (s *Server) createSessionAndRedirect(c *fiber.Ctx, u *ent.User) error {
	token, err := s.auth.CreateSession(c.Context(), u)
	if err != nil {
		return err
	}

	c.Cookie(&fiber.Cookie{
		Name:     auth.SessionCookie,
		Value:    token,
		HTTPOnly: true,
		Path:     "/",
		MaxAge:   30 * 24 * 60 * 60, // 30 days
		// Only over a TLS connection; c.Protocol() honours X-Forwarded-Proto
		// behind a reverse proxy.
		Secure: c.Protocol() == "https",
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

// sslGrades is the grade list offered by the dashboard's ssl_below filter,
// best first.
var sslGrades = []string{"A+", "A", "A-", "B", "C", "D", "E", "F"}

// dashboardParams are the query parameters the dashboard understands. Only
// these are carried into the links it builds.
var dashboardParams = []string{"state", "tag", "csp", "ssl", "ssl_below", "port", "expiring", "sort", "dir"}

const (
	defaultDashboardPageSize = 50
	// maxExpiringDays keeps days*24h, plus the 24h targetPredicates adds
	// on top (issue #42), inside time.Duration.
	maxExpiringDays = 100000
)

// parseDashboardQuery validates the dashboard's query parameters. An empty
// value counts as absent. Any invalid value is an error, so the handler can
// answer 400 instead of silently ignoring it.
func parseDashboardQuery(q url.Values) (storage.TargetFilter, storage.TargetSort, error) {
	var f storage.TargetFilter
	var sort storage.TargetSort

	if v := q.Get("state"); v != "" {
		st := target.Reachability(v)
		if target.ReachabilityValidator(st) != nil {
			return f, sort, invalidParam("state")
		}
		f.States = []target.Reachability{st}
	}
	f.Tag = q.Get("tag")

	switch v := q.Get("csp"); v {
	case "", "issues", "ok", "none":
		f.CSP = v
	default:
		return f, sort, invalidParam("csp")
	}

	if v := q.Get("ssl"); v != "" {
		if !storage.IsGrade(v) {
			return f, sort, invalidParam("ssl")
		}
		f.SSLGrade = v
	}
	if v := q.Get("ssl_below"); v != "" {
		if !storage.IsGrade(v) {
			return f, sort, invalidParam("ssl_below")
		}
		f.SSLBelow = v
	}

	if v := q.Get("port"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return f, sort, invalidParam("port")
		}
		f.Port = n
	}

	if v := q.Get("expiring"); v != "" {
		days, err := strconv.Atoi(v)
		if err != nil || days < 1 || days > maxExpiringDays {
			return f, sort, invalidParam("expiring")
		}
		f.ExpiringWithin = time.Duration(days) * 24 * time.Hour
	}

	sort.Field = storage.SortTarget
	if v := q.Get("sort"); v != "" {
		if !slices.Contains(storage.SortFields, v) {
			return f, sort, invalidParam("sort")
		}
		sort.Field = v
	}
	switch q.Get("dir") {
	case "", "asc":
	case "desc":
		sort.Desc = true
	default:
		return f, sort, invalidParam("dir")
	}

	return f, sort, nil
}

func invalidParam(name string) error {
	return fmt.Errorf("invalid %s", name)
}

// dashboardQuery returns the recognised, non-empty parameters of q. Call it
// only after parseDashboardQuery has accepted q.
func dashboardQuery(q url.Values) url.Values {
	out := url.Values{}
	for _, k := range dashboardParams {
		if v := q.Get(k); v != "" {
			out.Set(k, v)
		}
	}
	return out
}

// withQuery builds a dashboard URL from the current query q plus the key,
// value pairs in kv. An empty value deletes the key. "page" is never carried
// over from q, so any link that changes the filters or sort starts on page 1;
// it is only present when kv sets it.
func withQuery(q url.Values, kv ...string) (string, error) {
	if len(kv)%2 != 0 {
		return "", errors.New("withQuery: odd number of key/value arguments")
	}
	out := url.Values{}
	for k, vs := range q {
		if k == "page" {
			continue
		}
		out[k] = slices.Clone(vs)
	}
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == "" {
			out.Del(kv[i])
		} else {
			out.Set(kv[i], kv[i+1])
		}
	}
	enc := out.Encode()
	if enc == "" {
		return "/", nil
	}
	return "/?" + enc, nil
}

// sortHeader is one sortable column header: the link to click and the arrow
// shown when the column is the active sort.
type sortHeader struct {
	URL   string
	Arrow string
}

// descFirstSorts are the columns whose inactive header link starts
// descending: for SSL, worst grade first is the useful first click, since the
// active ascending direction is best grade first.
var descFirstSorts = map[string]bool{
	storage.SortSSL: true,
}

// sortHeaders builds the header link for every sort field. Clicking the
// active column toggles its direction; clicking another column starts it in
// its default direction (desc for descFirstSorts, asc for the rest).
func sortHeaders(q url.Values, cur storage.TargetSort) (map[string]sortHeader, error) {
	out := make(map[string]sortHeader, len(storage.SortFields))
	for _, field := range storage.SortFields {
		dir := "asc"
		if descFirstSorts[field] {
			dir = "desc"
		}
		var arrow string
		if field == cur.Field {
			if cur.Desc {
				arrow = " ▼"
				dir = "asc"
			} else {
				arrow = " ▲"
				dir = "desc"
			}
		}
		u, err := withQuery(q, "sort", field, "dir", dir)
		if err != nil {
			return nil, err
		}
		out[field] = sortHeader{URL: u, Arrow: arrow}
	}
	return out, nil
}

// dashboardPagination builds prev/next links that keep the current query.
func dashboardPagination(q url.Values, page, totalPages int) (pagination, error) {
	p := pagination{Page: page, TotalPages: totalPages}
	var err error
	if page > 1 {
		if p.PrevURL, err = withQuery(q, "page", strconv.Itoa(page-1)); err != nil {
			return p, err
		}
	}
	if page < totalPages {
		if p.NextURL, err = withQuery(q, "page", strconv.Itoa(page+1)); err != nil {
			return p, err
		}
	}
	return p, nil
}

// queryValues copies the request's query string into url.Values.
func queryValues(c *fiber.Ctx) url.Values {
	v := url.Values{}
	c.Context().QueryArgs().VisitAll(func(key, value []byte) {
		v.Add(string(key), string(value))
	})
	return v
}

func (s *Server) handleIndex(c *fiber.Ctx) error {
	raw := queryValues(c)
	filter, sort, err := parseDashboardQuery(raw)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	query := dashboardQuery(raw)

	ctx := c.Context()
	// The stat cards describe every target matching the filter, not the page.
	stats, err := s.storage.TargetStats(ctx, filter, time.Now(), s.certExpiryWindow)
	if err != nil {
		return err
	}

	pageSize := s.dashboardPageSize
	totalPages := max(1, (stats.Total+pageSize-1)/pageSize)
	page := clampPage(parsePage(c, "page"), stats.Total, pageSize)

	targets, err := s.storage.ListTargets(ctx, filter, sort, pageSize, (page-1)*pageSize)
	if err != nil {
		return err
	}

	allTags, _ := s.client.Tag.Query().All(ctx)

	deletedCount, err := s.storage.CountDeletedTargets(ctx)
	if err != nil {
		return err
	}

	// State counts ignore the active state filter, so every state link shows
	// how many targets the other filters would still match.
	stateCounts, err := s.storage.StateCounts(ctx, filter)
	if err != nil {
		return err
	}
	stateTotal := 0
	for _, n := range stateCounts {
		stateTotal += n
	}

	headers, err := sortHeaders(query, sort)
	if err != nil {
		return err
	}
	pag, err := dashboardPagination(query, page, totalPages)
	if err != nil {
		return err
	}
	clearURL, err := withQuery(query, "state", "", "tag", "", "csp", "", "ssl", "",
		"ssl_below", "", "port", "", "expiring", "")
	if err != nil {
		return err
	}

	return c.Render("views/index", s.templateData(c, fiber.Map{
		"Title":          "Perimeter Dashboard",
		"Targets":        targets,
		"Tags":           allTags,
		"States":         reachabilityStates,
		"SSLGrades":      sslGrades,
		"Query":          query,
		"FilterTag":      query.Get("tag"),
		"FilterState":    query.Get("state"),
		"FilterCSP":      query.Get("csp"),
		"FilterSSL":      query.Get("ssl"),
		"FilterSSLBelow": query.Get("ssl_below"),
		"FilterPort":     query.Get("port"),
		"FilterExpiring": query.Get("expiring"),
		"FilterSort":     query.Get("sort"),
		"FilterDir":      query.Get("dir"),
		"SortHeaders":    headers,
		"ClearURL":       clearURL,
		"Pagination":     pag,
		"TotalTargets":   stats.Total,
		"StateCounts":    stateCounts,
		"StateTotal":     stateTotal,
		"DeletedCount":   deletedCount,
		"TotalOpenPorts": stats.OpenPorts,
		"ExpiringCerts":  stats.ExpiringCerts,
		"CSPIssues":      stats.CSPIssues,
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

func clampPage(page, total, pageSize int) int {
	totalPages := (total + pageSize - 1) / pageSize
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
	if settled := clampPage(page, total, scanPageSize); settled != page {
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
	if settled := clampPage(page, total, scanPageSize); settled != page {
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
	if settled := clampPage(page, total, scanPageSize); settled != page {
		items, _, err = s.storage.GetIPScansPage(ctx, i.ID, scanPageSize+1, (settled-1)*scanPageSize)
		if err != nil {
			return ipScanRow{}, err
		}
		page = settled
	}
	return ipScanRow{IP: i, Scans: diffPortScans(items), Pagination: buildPagination(c, ipPageKey(i.ID), page, total)}, nil
}

// diffPortScans annotates each row with the ports gained and lost relative to
// the next older row that answered the scan. Rows arrive newest first; error
// rows show no diff and are skipped as baselines, and the trailing lookahead
// row is dropped after it has been used as a baseline.
func diffPortScans(items []*ent.PortScan) []portScanView {
	views := make([]portScanView, 0, len(items))
	for n, scan := range items {
		v := portScanView{PortScan: scan}
		if scan.ScanError == "" {
			for m := n + 1; m < len(items); m++ {
				if items[m].ScanError == "" {
					v.Added, v.Removed = portDelta(scanPorts(items[m]), scanPorts(scan))
					break
				}
			}
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
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	target, err := s.storage.GetTargetBasic(c.Context(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			return fiber.NewError(fiber.StatusNotFound, "Target not found")
		}
		return err
	}

	switch c.Query("fragment") {
	case "ssl":
		sslScans, sslPagination, err := s.sslHistoryData(c.Context(), c, target.ID)
		if err != nil {
			return err
		}
		return c.Render("views/partials/ssl_section", fiber.Map{
			"SSLScans":      sslScans,
			"SSLPagination": sslPagination,
		})
	case "csp":
		cspScans, cspPagination, err := s.cspHistoryData(c.Context(), c, target.ID)
		if err != nil {
			return err
		}
		return c.Render("views/partials/csp_section", fiber.Map{
			"CSPScans":      cspScans,
			"CSPPagination": cspPagination,
		})
	case "ip":
		ipID, err := strconv.Atoi(c.Query("ipId"))
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid ipId")
		}
		for _, i := range target.Edges.Ips {
			if i.ID == ipID {
				row, err := s.ipHistoryData(c.Context(), c, i)
				if err != nil {
					return err
				}
				return c.Render("views/partials/ip_section", row)
			}
		}
		return fiber.NewError(fiber.StatusNotFound, "IP not found")
	}

	sslScans, sslPagination, err := s.sslHistoryData(c.Context(), c, target.ID)
	if err != nil {
		return err
	}
	cspScans, cspPagination, err := s.cspHistoryData(c.Context(), c, target.ID)
	if err != nil {
		return err
	}
	ipRows := make([]ipScanRow, 0, len(target.Edges.Ips))
	for _, i := range target.Edges.Ips {
		row, err := s.ipHistoryData(c.Context(), c, i)
		if err != nil {
			return err
		}
		ipRows = append(ipRows, row)
	}

	allTags, _ := s.client.Tag.Query().All(c.Context())
	_, sslFailed, err := s.storage.GetLatestSSL(c.Context(), target.Input)
	if err != nil {
		return err
	}
	dnsChanges, _, err := s.storage.GetDNSChangesPage(c.Context(), target.ID, 10, 0)
	if err != nil {
		return err
	}

	return c.Render("views/target", s.templateData(c, fiber.Map{
		"Title":           "Target Details",
		"Target":          target,
		"AllTags":         allTags,
		"IPRows":          ipRows,
		"RescanRequested": rescanRequested(target),
		"SSLScans":        sslScans,
		"SSLPagination":   sslPagination,
		"SSLFailed":       sslFailed,
		"DNSChanges":      dnsChanges,
		"CSPScans":        cspScans,
		"CSPPagination":   cspPagination,
	}), "views/layouts/main")
}

func (s *Server) handleDeleteTarget(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	label := s.targetLabel(c.Context(), id)
	err = s.storage.DeleteTarget(c.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrTargetNotFound) || ent.IsNotFound(err) {
			return fiber.NewError(fiber.StatusNotFound, "Target not found")
		}
		return err
	}
	s.auditUI(c, "target.delete", label, "")

	setFlash(c, flash{Kind: "success", Message: fmt.Sprintf("Deleted %s. You can restore it from Deleted targets.", label)})
	return c.Redirect("/", fiber.StatusSeeOther)
}

// targetLabel is the input of a target, live or soft-deleted, for a flash
// message. A target that no longer exists is named by its id.
func (s *Server) targetLabel(ctx context.Context, id int) string {
	t, err := s.client.Target.Get(schema.SkipSoftDelete(ctx), id)
	if err != nil {
		return "target " + strconv.Itoa(id)
	}
	return t.Input
}

// auditUI records a write made from the web UI, after it succeeded, so a
// failed write leaves no row.
func (s *Server) auditUI(c *fiber.Ctx, action, object, detail string) {
	s.svc.Audit(c.Context(), service.Actor{User: auth.GetUser(c), Source: service.SourceUI}, action, object, detail)
}

// rescanKinds is what a rescan from this server queues: SSL only when SSL Labs
// scanning runs.
func (s *Server) rescanKinds() storage.RescanKinds {
	return storage.RescanKinds{SSL: s.sslScanning, CSP: true, Ports: true}
}

// rescanRequested returns when the pending rescan of t was requested, or nil
// when none is pending: no flag is set, or a stored result has cleared them.
func rescanRequested(t *ent.Target) *time.Time {
	if t.RescanRequestedAt == nil {
		return nil
	}
	if t.SslRescanPending || t.CspRescanPending {
		return t.RescanRequestedAt
	}
	for _, i := range t.Edges.Ips {
		if i.RescanPending {
			return t.RescanRequestedAt
		}
	}
	return nil
}

// handleRescanTarget queues an on-demand scan of one target. It flashes either
// that the rescan is queued, or when the target may be rescanned again.
func (s *Server) handleRescanTarget(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	label := s.targetLabel(c.Context(), id)
	res, err := s.storage.RequestRescan(c.Context(), []int{id}, time.Now(), s.rescanCooldown, s.rescanKinds())
	if err != nil {
		return err
	}
	if len(res.NotFound) > 0 {
		return fiber.NewError(fiber.StatusNotFound, "Target not found")
	}
	if len(res.CoolingDown) > 0 {
		s.auditUI(c, "target.rescan", label, "cooling down")
		retry := res.CoolingDown[0].RetryAt.Format("15:04")
		setFlash(c, flash{Kind: "error", Message: fmt.Sprintf("%s was rescanned recently; try again after %s.", label, retry)})
	} else {
		s.auditUI(c, "target.rescan", label, "queued")
		setFlash(c, flash{Kind: "success", Message: "Rescan queued for " + label + "."})
	}
	return c.Redirect("/targets/"+strconv.Itoa(id), fiber.StatusSeeOther)
}

func (s *Server) handleDeletedTargets(c *fiber.Ctx) error {
	targets, err := s.storage.ListDeletedTargets(c.Context())
	if err != nil {
		return err
	}

	return c.Render("views/deleted", s.templateData(c, fiber.Map{
		"Title":   "Deleted targets",
		"Targets": targets,
	}), "views/layouts/main")
}

func (s *Server) handleRestoreTarget(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	label := s.targetLabel(c.Context(), id)
	err = s.storage.RestoreTarget(c.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrTargetNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "Target not found")
		}
		return err
	}
	s.auditUI(c, "target.restore", label, "")

	setFlash(c, flash{Kind: "success", Message: "Restored " + label + "."})
	return c.Redirect("/targets/deleted", fiber.StatusSeeOther)
}

func (s *Server) handlePurgeTarget(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	label := s.targetLabel(c.Context(), id)
	err = s.storage.PurgeTarget(c.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrTargetNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "Target not found")
		}
		return err
	}
	s.auditUI(c, "target.purge", label, "")

	setFlash(c, flash{Kind: "success", Message: "Purged " + label + "."})
	return c.Redirect("/targets/deleted", fiber.StatusSeeOther)
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
		return fiber.NewError(fiber.StatusBadRequest, "Invalid source type")
	}

	targets, err := src.Fetch(c.Context())
	if err != nil {
		return err
	}

	res, err := s.storage.ImportTargetsReport(c.Context(), targets)
	if err != nil {
		return err
	}
	object, detail := service.ImportAudit(res)
	s.auditUI(c, "target.import", object, detail)

	// Re-render the form with the result so the user sees what happened; the
	// invalid lines are prefilled in the textarea for a fixed resubmit.
	return c.Render("views/import", s.templateData(c, fiber.Map{
		"Title":   "Import Targets",
		"Result":  res,
		"Prefill": strings.Join(res.Invalid, "\n"),
	}), "views/layouts/main")
}

// --- Admin handlers ---

func (s *Server) settingsData(c *fiber.Ctx, extra fiber.Map) fiber.Map {
	users, _ := s.client.User.Query().All(c.Context())
	apiTokens, _ := s.auth.ListAllAPITokens(c.Context())
	importers, _ := s.client.ImporterConfig.Query().All(c.Context())
	notifiers, _ := s.client.NotifierConfig.Query().All(c.Context())
	tags, _ := s.client.Tag.Query().All(c.Context())
	audit, _ := s.svc.ListAudit(c.Context(), auditSettingsSize, 0)
	providers := s.registry.List()
	notifierProviders := s.notifierRegistry.List()

	data := s.templateData(c, fiber.Map{
		"Title":              "Settings",
		"Users":              users,
		"APITokens":          apiTokens,
		"Importers":          importers,
		"Notifiers":          notifiers,
		"Tags":               tags,
		"AuditEvents":        audit.Items,
		"Providers":          providers,
		"NotifierProviders":  notifierProviders,
		"NotifierEventTypes": notifier.AllEventTypes(),
	})
	for k, v := range extra {
		data[k] = v
	}
	return data
}

func (s *Server) handleSettings(c *fiber.Ctx) error {
	return c.Render("views/settings", s.settingsData(c, nil), "views/layouts/main")
}

// auditSettingsSize is how many recent events the settings page lists.
const auditSettingsSize = 50

// auditPageSize is how many events each page of /settings/audit lists.
const auditPageSize = 50

// handleAuditPage shows the audit log, newest first, one page at a time. A
// page past the end shows the last one.
func (s *Server) handleAuditPage(c *fiber.Ctx) error {
	page := parsePage(c, "page")
	list, err := s.svc.ListAudit(c.Context(), auditPageSize, (page-1)*auditPageSize)
	if err != nil {
		return err
	}
	if last := clampPage(page, list.Total, auditPageSize); last != page {
		page = last
		if list, err = s.svc.ListAudit(c.Context(), auditPageSize, (page-1)*auditPageSize); err != nil {
			return err
		}
	}

	return c.Render("views/audit", s.templateData(c, fiber.Map{
		"Title":      "Audit log",
		"Events":     list.Items,
		"Pagination": auditPagination(c, page, list.Total),
	}), "views/layouts/main")
}

// auditPagination is the pager for the audit log. It is built here because
// buildPagination counts in scan pages.
func auditPagination(c *fiber.Ctx, page, total int) pagination {
	totalPages := max(1, (total+auditPageSize-1)/auditPageSize)
	p := pagination{Page: page, TotalPages: totalPages}
	if page > 1 {
		p.PrevURL = buildPageLink(c, "page", page-1)
	}
	if page < totalPages {
		p.NextURL = buildPageLink(c, "page", page+1)
	}
	return p
}

// userLabel is a user's email for an audit row. A user that no longer exists
// is named by its id.
func (s *Server) userLabel(ctx context.Context, id int) string {
	u, err := s.client.User.Get(ctx, id)
	if err != nil {
		return "user " + strconv.Itoa(id)
	}
	return u.Email
}

// importerLabel is the provider of an importer for an audit row. A missing
// importer is named by its id.
func (s *Server) importerLabel(ctx context.Context, id int) string {
	cfg, err := s.client.ImporterConfig.Get(ctx, id)
	if err != nil {
		return "importer " + strconv.Itoa(id)
	}
	return string(cfg.Provider)
}

// notifierLabel is the provider of a notifier for an audit row. A missing
// notifier is named by its id.
func (s *Server) notifierLabel(ctx context.Context, id int) string {
	cfg, err := s.client.NotifierConfig.Get(ctx, id)
	if err != nil {
		return "notifier " + strconv.Itoa(id)
	}
	return string(cfg.Provider)
}

// tagLabel is a tag's name for an audit row. A missing tag is named by its id.
func (s *Server) tagLabel(ctx context.Context, id int) string {
	t, err := s.client.Tag.Get(ctx, id)
	if err != nil {
		return "tag " + strconv.Itoa(id)
	}
	return t.Name
}

// userError turns an error from a settings action into a message that is
// safe to show: a missing row and a taken name get a sentence, auth's
// user-facing validation errors keep theirs, and anything else is logged
// and genericised so driver errors never reach the page.
func userError(action string, err error) string {
	switch {
	case ent.IsNotFound(err):
		return "Failed to " + action + ": it no longer exists"
	case ent.IsConstraintError(err):
		// Driver messages name the column: SQLite says
		// "UNIQUE constraint failed: tags.name", Postgres
		// `unique constraint "tags_name_key"`.
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "name") && strings.Contains(msg, "unique") {
			return "Failed to " + action + ": an entry with that name already exists"
		}
		return "Failed to " + action + ": it conflicts with an existing entry"
	case errors.Is(err, auth.ErrEmailTaken) || errors.Is(err, auth.ErrNotAllowed):
		return "Failed to " + action + ": " + err.Error()
	default:
		log.Printf("%s: %v", action, err)
		return "Failed to " + action + ". Check the server log for details."
	}
}

func (s *Server) handleInvite(c *fiber.Ctx) error {
	u := auth.GetUser(c)
	email := c.FormValue("email")
	role := c.FormValue("role")

	inviteRole := user.RoleMember
	switch role {
	case "admin":
		inviteRole = user.RoleAdmin
	case "viewer":
		inviteRole = user.RoleViewer
	}

	token, err := s.auth.CreateInvite(c.Context(), u, email, inviteRole)
	if err != nil {
		setFlash(c, flash{
			Kind:    "error",
			Message: userError("create invite", err),
			Form:    map[string]string{"email": email, "role": role},
		})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	s.auditUI(c, "user.invite", email, inviteRole.String())
	inviteLink := fmt.Sprintf("%s/register/%s", c.BaseURL(), token)
	setFlash(c, flash{
		Kind:       "success",
		Message:    "Invite created for " + email + ".",
		InviteLink: inviteLink,
	})
	return c.Redirect("/settings", fiber.StatusSeeOther)
}

func (s *Server) handleUsers(c *fiber.Ctx) error {
	return c.Redirect("/settings")
}

func (s *Server) handleDeleteUser(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	// Don't allow deleting yourself
	currentUser := auth.GetUser(c)
	if currentUser.ID == id {
		setFlash(c, flash{Kind: "error", Message: "Cannot delete your own account"})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	label := s.userLabel(c.Context(), id)
	if err := s.auth.DeleteUser(c.Context(), id); err != nil {
		if ent.IsNotFound(err) {
			return fiber.NewError(fiber.StatusNotFound, "User not found")
		}
		log.Printf("delete user %d: %v", id, err)
		setFlash(c, flash{Kind: "error", Message: "Could not delete the user. Check the server log for details."})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	s.auditUI(c, "user.delete", label, "")
	setFlash(c, flash{Kind: "success", Message: "User deleted."})
	return c.Redirect("/settings", fiber.StatusSeeOther)
}

// handleChangeRole sets a user's role. Admins are locked: an admin's role can
// not be changed from here, so at least one admin always remains and admins
// cannot demote each other.
func (s *Server) handleChangeRole(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	role := user.Role(c.FormValue("role"))
	if user.RoleValidator(role) != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid role")
	}

	currentUser := auth.GetUser(c)
	if currentUser.ID == id {
		setFlash(c, flash{Kind: "error", Message: "Cannot change your own role."})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	target, err := s.client.User.Get(c.Context(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			return fiber.NewError(fiber.StatusNotFound, "User not found")
		}
		return err
	}

	if target.Role == user.RoleAdmin {
		return fiber.NewError(fiber.StatusForbidden, "An admin's role cannot be changed")
	}

	if target.Role == role {
		setFlash(c, flash{Kind: "success", Message: target.Email + " is already a " + role.String() + "."})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	// The admin check is repeated in the update, so a user promoted by another
	// admin since the read above is not demoted.
	n, err := s.client.User.Update().
		Where(user.ID(id), user.RoleNEQ(user.RoleAdmin)).
		SetRole(role).
		Save(c.Context())
	if err != nil {
		log.Printf("change role of user %d to %s: %v", id, role, err)
		setFlash(c, flash{Kind: "error", Message: "Could not change the role. Check the server log for details."})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}
	if n == 0 {
		return fiber.NewError(fiber.StatusForbidden, "An admin's role cannot be changed")
	}

	s.auditUI(c, "user.role", target.Email, "role "+role.String())
	article := "a "
	if role == user.RoleAdmin {
		article = "an "
	}
	setFlash(c, flash{Kind: "success", Message: target.Email + " is now " + article + role.String() + "."})
	return c.Redirect("/settings", fiber.StatusSeeOther)
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
		setFlash(c, flash{
			Kind:    "error",
			Message: "Invalid importer config: " + err.Error(),
			Form:    importerForm(provider, intervalStr, credentials),
		})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	_, err = s.client.ImporterConfig.Create().
		SetProvider(importerconfig.Provider(provider)).
		SetCredentials([]byte(credentials)).
		SetSyncIntervalSeconds(interval).
		SetEnabled(true).
		Save(c.Context())
	if err != nil {
		setFlash(c, flash{
			Kind:    "error",
			Message: userError("create importer", err),
			Form:    importerForm(provider, intervalStr, credentials),
		})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	s.auditUI(c, "importer.create", provider, "")
	setFlash(c, flash{Kind: "success", Message: "Importer added. The first sync is running."})
	return c.Redirect("/settings", fiber.StatusSeeOther)
}

// importerForm keeps the non-secret fields of a rejected importer form so the
// page can prefill them. Only the dns_bruteforce domain is read out of the
// credentials; tokens, passwords and keys are never kept.
func importerForm(provider, interval, credentials string) map[string]string {
	form := map[string]string{"provider": provider, "sync_interval": interval}
	if provider == "dns_bruteforce" {
		var cfg struct {
			Domain string `json:"domain"`
		}
		if json.Unmarshal([]byte(credentials), &cfg) == nil {
			form["domain"] = cfg.Domain
		}
	}
	return form
}

func (s *Server) handleDeleteImporter(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	label := s.importerLabel(c.Context(), id)
	if err := s.client.ImporterConfig.DeleteOneID(id).Exec(c.Context()); err != nil {
		setFlash(c, flash{Kind: "error", Message: userError("delete importer", err)})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	s.auditUI(c, "importer.delete", label, "")
	setFlash(c, flash{Kind: "success", Message: "Importer deleted."})
	return c.Redirect("/settings", fiber.StatusSeeOther)
}

func (s *Server) handleToggleImporter(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	cfg, err := s.client.ImporterConfig.Get(c.Context(), id)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Importer not found")
	}

	if err := s.client.ImporterConfig.UpdateOne(cfg).SetEnabled(!cfg.Enabled).Exec(c.Context()); err != nil {
		return err
	}
	state := "disabled"
	if !cfg.Enabled {
		state = "enabled"
	}
	s.auditUI(c, "importer.toggle", string(cfg.Provider), state)
	setFlash(c, flash{Kind: "success", Message: "Importer " + state + "."})
	return c.Redirect("/settings", fiber.StatusSeeOther)
}

// handleSyncImporter runs one importer immediately ("Sync now") and shows
// the result on the settings page.
func (s *Server) handleSyncImporter(c *fiber.Ctx) error {
	if s.syncer == nil {
		setFlash(c, flash{Kind: "error", Message: "Sync not available"})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	cfg, err := s.client.ImporterConfig.Get(c.Context(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			return fiber.NewError(fiber.StatusNotFound, "Importer not found")
		}
		return err
	}

	// Provider APIs are slow; do not hold the request open forever.
	ctx, cancel := context.WithTimeout(c.Context(), 2*time.Minute)
	defer cancel()
	count, err := s.syncer.SyncOne(ctx, cfg)
	if err != nil {
		msg := "Sync failed: " + err.Error()
		var partial *importer.ZoneErrors
		if errors.As(err, &partial) {
			msg = fmt.Sprintf("Sync incomplete: %d targets imported, but some zones failed to load (%v). It counts as failed and is retried.", count, err)
		}
		if errors.Is(err, importer.ErrSyncRunning) {
			msg = "A sync for this importer is already running (one starts automatically when an importer is added). Refresh in a minute to see the result."
		}
		setFlash(c, flash{Kind: "error", Message: msg})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	setFlash(c, flash{Kind: "success", Message: fmt.Sprintf("Synced %s: %d targets imported", cfg.Provider, count)})
	return c.Redirect("/settings", fiber.StatusSeeOther)
}

// --- Notifier handlers ---

// notifierEventLabels are the human labels for event types, used by the
// settings checkboxes and the notifier table.
var notifierEventLabels = map[string]string{
	string(notifier.EventNewOpenPorts): "New open ports",
	string(notifier.EventSSLGradeDrop): "SSL grade drop",
	string(notifier.EventCertExpiring): "Certificate expiring",
	string(notifier.EventCSPIssues):    "CSP issues",
}

// notifierEventLabel is the template func behind eventLabel. It takes any so
// templates can pass a notifier.EventType or a plain string.
func notifierEventLabel(v any) string {
	name := fmt.Sprint(v)
	if label, ok := notifierEventLabels[name]; ok {
		return label
	}
	return name
}

// parseNotifierEvents turns the submitted event checkboxes into the list to
// store. It returns nil when every event type is selected, so the notifier
// also gets event types added later. Values are normalised to declaration order.
func parseNotifierEvents(values [][]byte) ([]string, error) {
	selected := make(map[string]bool, len(values))
	for _, v := range values {
		name := string(v)
		if !slices.ContainsFunc(notifier.AllEventTypes(), func(t notifier.EventType) bool {
			return string(t) == name
		}) {
			return nil, fmt.Errorf("unknown event type: %s", name)
		}
		selected[name] = true
	}
	if len(selected) == 0 {
		return nil, errors.New("select at least one event type")
	}

	all := notifier.AllEventTypes()
	events := make([]string, 0, len(selected))
	for _, t := range all {
		if selected[string(t)] {
			events = append(events, string(t))
		}
	}
	if len(events) == len(all) {
		return nil, nil
	}
	return events, nil
}

func (s *Server) handleCreateNotifier(c *fiber.Ctx) error {
	provider := c.FormValue("provider")
	config := c.FormValue("config")

	// The checkboxes share one name, so read every value rather than the first.
	rawEvents := c.Request().PostArgs().PeekMulti("events")
	events, err := parseNotifierEvents(rawEvents)
	if err != nil {
		setFlash(c, flash{
			Kind:    "error",
			Message: "Invalid notifier events: " + err.Error(),
			Form:    notifierForm(provider, rawEvents, config),
		})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	// Check the config now so a bad URL or address fails here, not in the
	// background dispatcher.
	if _, err := s.notifierRegistry.Get(provider, json.RawMessage(config)); err != nil {
		setFlash(c, flash{
			Kind:    "error",
			Message: "Invalid notifier config: " + err.Error(),
			Form:    notifierForm(provider, rawEvents, config),
		})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	create := s.client.NotifierConfig.Create().
		SetProvider(notifierconfig.Provider(provider)).
		SetConfig([]byte(config)).
		SetEnabled(true)
	if events != nil {
		create.SetEvents(events)
	}
	if _, err := create.Save(c.Context()); err != nil {
		setFlash(c, flash{
			Kind:    "error",
			Message: userError("create notifier", err),
			Form:    notifierForm(provider, rawEvents, config),
		})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	s.auditUI(c, "notifier.create", provider, "")
	setFlash(c, flash{Kind: "success", Message: "Notifier added."})
	return c.Redirect("/settings", fiber.StatusSeeOther)
}

// notifierForm keeps the non-secret fields of a rejected notifier form so the
// page can prefill them: the provider, the ticked events, the email recipients
// and the webhook URL. Anything else in the config is not kept.
func notifierForm(provider string, rawEvents [][]byte, config string) map[string]string {
	events := make([]string, 0, len(rawEvents))
	for _, e := range rawEvents {
		events = append(events, string(e))
	}
	form := map[string]string{"provider": provider, "events": strings.Join(events, ",")}

	var cfg struct {
		To  []string `json:"to"`
		URL string   `json:"url"`
	}
	if json.Unmarshal([]byte(config), &cfg) == nil {
		switch provider {
		case "email":
			form["recipients"] = strings.Join(cfg.To, "\n")
		case "webhook":
			form["url"] = cfg.URL
		}
	}
	return form
}

func (s *Server) handleDeleteNotifier(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	label := s.notifierLabel(c.Context(), id)
	if err := s.client.NotifierConfig.DeleteOneID(id).Exec(c.Context()); err != nil {
		setFlash(c, flash{Kind: "error", Message: userError("delete notifier", err)})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	s.auditUI(c, "notifier.delete", label, "")
	setFlash(c, flash{Kind: "success", Message: "Notifier deleted."})
	return c.Redirect("/settings", fiber.StatusSeeOther)
}

func (s *Server) handleToggleNotifier(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	cfg, err := s.client.NotifierConfig.Get(c.Context(), id)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Notifier not found")
	}

	if err := s.client.NotifierConfig.UpdateOne(cfg).SetEnabled(!cfg.Enabled).Exec(c.Context()); err != nil {
		return err
	}
	state := "disabled"
	if !cfg.Enabled {
		state = "enabled"
	}
	s.auditUI(c, "notifier.toggle", string(cfg.Provider), state)
	setFlash(c, flash{Kind: "success", Message: "Notifier " + state + "."})
	return c.Redirect("/settings", fiber.StatusSeeOther)
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
		setFlash(c, flash{Kind: "error", Message: userError("create tag", err)})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	s.auditUI(c, "tag.create", name, "")
	setFlash(c, flash{Kind: "success", Message: fmt.Sprintf(`Tag "%s" created.`, name)})
	return c.Redirect("/settings", fiber.StatusSeeOther)
}

func (s *Server) handleDeleteTag(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	label := s.tagLabel(c.Context(), id)
	if err := s.client.Tag.DeleteOneID(id).Exec(c.Context()); err != nil {
		setFlash(c, flash{Kind: "error", Message: userError("delete tag", err)})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	s.auditUI(c, "tag.delete", label, "")
	setFlash(c, flash{Kind: "success", Message: "Tag deleted."})
	return c.Redirect("/settings", fiber.StatusSeeOther)
}

func (s *Server) handleUpdateTargetTags(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	t, err := s.client.Target.Get(c.Context(), id)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Target not found")
	}

	// Get selected tag IDs from form. A bad or unknown id rejects the whole
	// request, so a failed submission cannot wipe the tags.
	tagIDs := c.Context().PostArgs().PeekMulti("tags")
	seen := make(map[int]bool)
	var ids []int
	var names []string
	for _, raw := range tagIDs {
		tid, err := strconv.Atoi(string(raw))
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid tag id")
		}
		if !seen[tid] {
			seen[tid] = true
			ids = append(ids, tid)
		}
	}
	if len(ids) > 0 {
		found, err := s.client.Tag.Query().Where(tag.IDIn(ids...)).All(c.Context())
		if err != nil {
			return err
		}
		if len(found) != len(ids) {
			return fiber.NewError(fiber.StatusBadRequest, "Unknown tag")
		}
		for _, g := range found {
			names = append(names, g.Name)
		}
	}

	// Clear existing tags and set the new ones in one update; no values
	// clears all tags.
	if err := s.client.Target.UpdateOne(t).ClearTags().AddTagIDs(ids...).Exec(c.Context()); err != nil {
		return err
	}

	slices.Sort(names)
	detail := "tags cleared"
	if len(names) > 0 {
		detail = "tags set to " + strings.Join(names, ", ")
	}
	s.auditUI(c, "target.tags", t.Input, detail)
	setFlash(c, flash{Kind: "success", Message: "Tags updated."})
	return c.Redirect(fmt.Sprintf("/targets/%d", id), fiber.StatusSeeOther)
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
	Error     string `json:"error,omitempty"`
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
	ScannedAt    string `json:"scanned_at"`
	Header       string `json:"csp_header"`
	Findings     int    `json:"findings_count"`
	ProbeError   string `json:"probe_error,omitempty"`
	StatusCode   int    `json:"status_code,omitempty"`
	FinalURL     string `json:"final_url,omitempty"`
	TLSProblem   string `json:"tls_problem,omitempty"`
	RedirectHost string `json:"redirect_host,omitempty"`
}

// newExportData gathers the export view of a target. The target must come
// from a query that loaded its full history (GetTarget or
// EachTargetWithHistory).
func newExportData(t *ent.Target) exportData {
	data := exportData{
		Target:       t.Input,
		IsIP:         t.IsIP,
		Reachability: string(t.Reachability),
	}

	for _, ip := range t.Edges.Ips {
		eip := exportIP{Address: ip.Address}
		for _, scan := range ip.Edges.Scans {
			// Ports is always a non-nil slice so an empty successful scan
			// exports as [], not null.
			ports := make([]int, 0, len(scan.Edges.Ports))
			for _, p := range scan.Edges.Ports {
				ports = append(ports, p.Number)
			}
			eip.Scans = append(eip.Scans, exportPortScan{
				ScannedAt: scan.ScannedAt.Format(time.RFC3339),
				Ports:     ports,
				Error:     scan.ScanError,
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
			ScannedAt:    scan.ScannedAt.Format(time.RFC3339),
			Header:       scan.CspHeader,
			Findings:     len(scan.Findings),
			ProbeError:   scan.ProbeError,
			StatusCode:   scan.StatusCode,
			FinalURL:     scan.FinalURL,
			TLSProblem:   scan.TLSProblem,
			RedirectHost: scan.RedirectHost,
		})
	}

	return data
}

// exportCSVRows returns the data rows of a target's CSV export, without the
// header. Each row is type, timestamp, detail, value.
func exportCSVRows(d exportData) [][]string {
	var rows [][]string
	for _, ip := range d.IPs {
		for _, scan := range ip.Scans {
			value := ""
			if scan.Error != "" {
				value = scan.Error
			} else {
				portStrs := make([]string, len(scan.Ports))
				for i, p := range scan.Ports {
					portStrs[i] = strconv.Itoa(p)
				}
				value = strings.Join(portStrs, ";")
			}
			rows = append(rows, []string{"port_scan", scan.ScannedAt, ip.Address, value})
		}
	}
	for _, scan := range d.SSL {
		rows = append(rows, []string{"ssl_scan", scan.ScannedAt, scan.Grade, scan.Status})
	}
	for _, scan := range d.CSP {
		detail := strconv.Itoa(scan.Findings) + " findings"
		if scan.ProbeError != "" {
			detail = "no HTTP response: " + scan.ProbeError
		} else if scan.RedirectHost != "" {
			detail = "redirects to " + scan.RedirectHost
		} else if scan.StatusCode != 0 && !storage.StatusServesApp(scan.StatusCode) {
			detail = fmt.Sprintf("no application served (%d)", scan.StatusCode)
		}
		rows = append(rows, []string{"csp_scan", scan.ScannedAt, detail, scan.Header})
	}
	return rows
}

func (s *Server) handleExportTarget(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	t, err := s.storage.GetTarget(c.Context(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			return fiber.NewError(fiber.StatusNotFound, "Target not found")
		}
		return err
	}

	format := c.Query("format", "json")
	data := newExportData(t)

	switch format {
	case "csv":
		c.Set("Content-Type", "text/csv")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", t.Input))

		rows := append([][]string{{"type", "timestamp", "detail", "value"}}, exportCSVRows(data)...)

		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		if err := w.WriteAll(rows); err != nil {
			return err
		}
		return c.Send(buf.Bytes())

	default:
		c.Set("Content-Type", "application/json")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.json", t.Input))
		out, _ := json.MarshalIndent(data, "", "  ")
		return c.Send(out)
	}
}

// --- Bulk actions (issue #18) ---

// badRequest is a selection or parameter the client got wrong. The bulk
// handlers answer it with 400; any other error is a 500.
type badRequest struct{ msg string }

func (e badRequest) Error() string { return e.msg }

// bulkError maps an error from bulkSelection to a response: a badRequest is
// a 400 with its message, anything else goes to the error handler.
func bulkError(err error) error {
	var bad badRequest
	if errors.As(err, &bad) {
		return fiber.NewError(fiber.StatusBadRequest, bad.msg)
	}
	return err
}

// bulkSelection resolves the targets a bulk request acts on. With form value
// all == "1" the selection is every live target matching the dashboard
// filter in the form; otherwise it is the ids form values.
func (s *Server) bulkSelection(c *fiber.Ctx) ([]int, error) {
	args := c.Request().PostArgs()

	if string(args.Peek("all")) == "1" {
		q := url.Values{}
		for _, k := range dashboardParams {
			if v := args.Peek(k); len(v) > 0 {
				q.Set(k, string(v))
			}
		}
		filter, _, err := parseDashboardQuery(q)
		if err != nil {
			return nil, badRequest{err.Error()}
		}
		ids, err := s.storage.TargetIDs(c.Context(), filter)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			return nil, badRequest{"No targets selected"}
		}
		return ids, nil
	}

	var ids []int
	for _, raw := range args.PeekMulti("ids") {
		id, err := strconv.Atoi(string(raw))
		if err != nil || id < 1 {
			return nil, badRequest{"Invalid target ID"}
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, badRequest{"No targets selected"}
	}
	// Duplicates would inflate the count the confirmation page shows.
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// handleBulkExport streams the selected targets as one JSON array or CSV file.
// The selection is resolved before the response starts, so a bad request is
// still a 400. Errors once streaming has begun can only be logged.
func (s *Server) handleBulkExport(c *fiber.Ctx) error {
	format := string(c.Request().PostArgs().Peek("format"))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid format")
	}

	ids, err := s.bulkSelection(c)
	if err != nil {
		return bulkError(err)
	}

	// The stream writer runs after this handler returns, when c has been
	// recycled, so nothing below may touch c.
	ctx := context.Background()
	day := time.Now().UTC().Format("20060102")

	if format == "csv" {
		c.Set("Content-Type", "text/csv")
		c.Set("Content-Disposition", "attachment; filename=perimeter-targets-"+day+".csv")
		c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
			s.streamBulkCSV(ctx, w, ids)
		})
		return nil
	}

	c.Set("Content-Type", "application/json")
	c.Set("Content-Disposition", "attachment; filename=perimeter-targets-"+day+".json")
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		s.streamBulkJSON(ctx, w, ids)
	})
	return nil
}

// streamBulkJSON writes a JSON array with one exportData per target. On error
// the array is left unclosed, so a truncated download does not parse.
func (s *Server) streamBulkJSON(ctx context.Context, w *bufio.Writer, ids []int) {
	if _, err := w.WriteString("[\n"); err != nil {
		log.Printf("bulk export: %v", err)
		return
	}
	first := true
	err := s.storage.EachTargetWithHistory(ctx, ids, func(t *ent.Target) error {
		if !first {
			if _, err := w.WriteString(",\n"); err != nil {
				return err
			}
		}
		first = false
		out, err := json.MarshalIndent(newExportData(t), "  ", "  ")
		if err != nil {
			return err
		}
		if _, err := w.WriteString("  "); err != nil {
			return err
		}
		_, err = w.Write(out)
		return err
	})
	if err != nil {
		log.Printf("bulk export: %v", err)
		return
	}
	if _, err := w.WriteString("\n]\n"); err != nil {
		log.Printf("bulk export: %v", err)
	}
}

// streamBulkCSV writes one CSV with a target column in front of each row of
// the single-target export.
func (s *Server) streamBulkCSV(ctx context.Context, w *bufio.Writer, ids []int) {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"target", "type", "timestamp", "detail", "value"}); err != nil {
		log.Printf("bulk export: %v", err)
		return
	}
	cw.Flush()
	err := s.storage.EachTargetWithHistory(ctx, ids, func(t *ent.Target) error {
		d := newExportData(t)
		for _, row := range exportCSVRows(d) {
			if err := cw.Write(append([]string{d.Target}, row...)); err != nil {
				return err
			}
		}
		cw.Flush()
		return cw.Error()
	})
	if err != nil {
		log.Printf("bulk export: %v", err)
	}
}

// bulkDeletePreview is how many targets the delete confirmation names.
const bulkDeletePreview = 20

// handleBulkDelete asks for confirmation, then soft-deletes the resolved
// selection. The confirmation form posts the resolved ids, never all=1, so
// the targets deleted are exactly the ones the user saw counted.
func (s *Server) handleBulkDelete(c *fiber.Ctx) error {
	ids, err := s.bulkSelection(c)
	if err != nil {
		return bulkError(err)
	}

	if string(c.Request().PostArgs().Peek("confirm")) != "1" {
		return s.renderBulkDeleteConfirm(c, ids)
	}

	n, err := s.storage.DeleteTargets(c.Context(), ids)
	if err != nil {
		return err
	}
	s.auditUI(c, "target.delete", fmt.Sprintf("%d targets", n), "")
	noun := "targets"
	if n == 1 {
		noun = "target"
	}
	setFlash(c, flash{Kind: "success", Message: fmt.Sprintf("Deleted %d %s.", n, noun)})
	return c.Redirect("/", fiber.StatusSeeOther)
}

// handleBulkRescan queues a rescan of the resolved selection. Unlike delete it
// needs no confirmation: a rescan changes no targets, only the scan queue.
func (s *Server) handleBulkRescan(c *fiber.Ctx) error {
	ids, err := s.bulkSelection(c)
	if err != nil {
		return bulkError(err)
	}

	res, err := s.storage.RequestRescan(c.Context(), ids, time.Now(), s.rescanCooldown, s.rescanKinds())
	if err != nil {
		return err
	}
	s.auditUI(c, "target.rescan", fmt.Sprintf("%d targets", len(ids)), fmt.Sprintf("%d queued, %d cooling down", len(res.Queued), len(res.CoolingDown)))
	setFlash(c, flash{Kind: "success", Message: fmt.Sprintf("Rescan queued for %d targets (%d cooling down).", len(res.Queued), len(res.CoolingDown))})
	return c.Redirect("/", fiber.StatusSeeOther)
}

func (s *Server) renderBulkDeleteConfirm(c *fiber.Ctx, ids []int) error {
	preview := ids[:min(bulkDeletePreview, len(ids))]
	targets, err := s.client.Target.Query().
		Where(target.IDIn(preview...)).
		Order(ent.Asc(target.FieldInput)).
		All(c.Context())
	if err != nil {
		return err
	}

	return c.Render("views/bulk_delete", s.templateData(c, fiber.Map{
		"Title":   "Delete targets",
		"IDs":     ids,
		"Count":   len(ids),
		"Targets": targets,
		"More":    len(ids) - len(preview),
	}), "views/layouts/main")
}
