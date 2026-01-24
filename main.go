package main

import (
	"embed"
	"log"
	"net/http"
	"perimeter/scanner/ports"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

//go:embed views/*
var viewsfs embed.FS

func main() {
	scanner := ports.NewSimpleScanner(10, 100, 1)
	ports, err := scanner.Scan("127.0.0.1")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(ports)

	engine := html.NewFileSystem(http.FS(viewsfs), ".html")

	// Pass the engine to the Views
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	app.Get("/", func(c *fiber.Ctx) error {
		// Render index - start with views directory
		return c.Render("views/index", fiber.Map{
			"Title": "Hello, World!",
			"Ports": ports,
		}, "views/layouts/main")
	})

	log.Fatal(app.Listen(":3000"))
}
