package server

import (
	"io/fs"
	"net/http"
	"strconv"

	"perimeter/ent"
	"perimeter/internal/importer"
	"perimeter/internal/storage"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

type Server struct {
	app     *fiber.App
	storage storage.Storage
}

func New(s storage.Storage, viewsFS fs.FS) *Server {
	// Initialize View Engine
	// If viewsFS is embedded, we use http.FS to adapt it
	engine := html.NewFileSystem(http.FS(viewsFS), ".html")

	// Create Fiber App
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	srv := &Server{
		app:     app,
		storage: s,
	}

	srv.setupRoutes()
	return srv
}

func (s *Server) Listen(addr string) error {
	return s.app.Listen(addr)
}

func (s *Server) setupRoutes() {
	s.app.Get("/", s.handleIndex)
	s.app.Get("/targets/:id", s.handleTargetDetails)
	s.app.Get("/import", s.handleImport)
	s.app.Post("/import", s.handleImportSubmit)
	s.app.Post("/targets/:id/delete", s.handleDeleteTarget)
}

func (s *Server) handleIndex(c *fiber.Ctx) error {
	targets, err := s.storage.GetTargets(c.Context())
	if err != nil {
		return c.Status(500).SendString(err.Error())
	}

	return c.Render("views/index", fiber.Map{
		"Title":   "Perimeter Dashboard",
		"Targets": targets,
	}, "views/layouts/main")
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

	return c.Render("views/target", fiber.Map{
		"Title":  "Target Details",
		"Target": target,
	}, "views/layouts/main")
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
	return c.Render("views/import", fiber.Map{
		"Title": "Import Targets",
	}, "views/layouts/main")
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
