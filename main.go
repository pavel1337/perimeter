package main

import (
	"bufio"
	"context"
	"embed"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	_ "github.com/mattn/go-sqlite3"

	"perimeter/ent"
	"perimeter/ent/target"
	"perimeter/scanner/ports"
)

//go:embed views/*
var viewsfs embed.FS

func main() {
	// 1. Parse CLI Flags
	targetFile := flag.String("targets", "", "Path to text file containing targets (one per line)")
	httpPort := flag.String("port", "3000", "HTTP listen port")
	flag.Parse()

	if *targetFile == "" {
		log.Fatal("Error: You must provide a target list. Usage: ./perimeter -targets=hosts.txt")
	}

	// 2. Initialize Database (SQLite)
	client, err := ent.Open("sqlite3", "file:perimeter.db?cache=shared&_fk=1")
	if err != nil {
		log.Fatalf("failed opening connection to sqlite: %v", err)
	}
	defer client.Close()

	// Auto-Migration (Create Tables)
	if err := client.Schema.Create(context.Background()); err != nil {
		log.Fatalf("failed creating schema resources: %v", err)
	}

	// 3. Import Targets from File
	ctx := context.Background()
	if err := importTargets(ctx, client, *targetFile); err != nil {
		log.Fatalf("Failed to import targets: %v", err)
	}

	// 4. Start the Scanner Loop (Background Worker)
	// We pass the client so it can save results
	go runScanLoop(client)

	// 5. Start Web Server
	engine := html.NewFileSystem(http.FS(viewsfs), ".html")
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	app.Get("/", func(c *fiber.Ctx) error {
		// Fetch all targets and their LATEST scan
		targets, err := client.Target.Query().
			WithScans(func(q *ent.PortScanQuery) {
				q.WithPorts()
			}).
			All(c.Context())

		if err != nil {
			return c.Status(500).SendString(err.Error())
		}

		return c.Render("views/index", fiber.Map{
			"Title":   "Perimeter Dashboard",
			"Targets": targets,
		}, "views/layouts/main")
	})

	log.Printf("Perimeter is running on http://localhost:%s", *httpPort)
	log.Fatal(app.Listen(":" + *httpPort))
}

// ---------------------------------------------------------
// Helper: File Import
// ---------------------------------------------------------
func importTargets(ctx context.Context, client *ent.Client, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Idempotent Insert: Check if exists, if not create.
		exists, _ := client.Target.Query().Where(target.InputEQ(line)).Exist(ctx)
		if !exists {
			_, err := client.Target.Create().SetInput(line).Save(ctx)
			if err != nil {
				log.Printf("Error adding %s: %v", line, err)
			} else {
				count++
			}
		}
	}
	log.Printf("Imported %d new targets from %s", count, path)
	return scanner.Err()
}

// ---------------------------------------------------------
// Helper: The Scanner Loop
// ---------------------------------------------------------
func runScanLoop(client *ent.Client) {
	// Scanner Config: 500ms timeout, 100 concurrent threads
	portScanner := ports.NewSimpleScanner(1000, 100, 3)
	ctx := context.Background()

	for {
		log.Println("--- Starting Scan Cycle ---")

		// 1. Get all targets
		targets, err := client.Target.Query().WithScans().All(ctx)
		if err != nil {
			log.Printf("DB Error: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		for _, t := range targets {
			// Check if target had recent scans
			if len(t.Edges.Scans) > 0 {
				lastScan := t.Edges.Scans[0]
				if time.Since(lastScan.ScannedAt) < 1*time.Hour {
					continue
				}
			}

			log.Printf("Scanning %s...", t.Input)

			// 2. Perform Scan
			openPorts, err := portScanner.Scan(t.Input)
			if err != nil {
				log.Printf("Failed to scan %s: %v", t.Input, err)
				continue
			}

			// 3. Save History (Create Scan + Ports)
			// We wrap this in a transaction implicitly by using the builders
			scan, err := client.PortScan.Create().
				SetTarget(t).
				SetScannedAt(time.Now()).
				Save(ctx)

			if err != nil {
				log.Printf("Failed to save scan record: %v", err)
				continue
			}

			// Bulk insert open ports
			if len(openPorts) > 0 {
				builders := make([]*ent.PortCreate, len(openPorts))
				for i, p := range openPorts {
					builders[i] = client.Port.Create().
						SetScan(scan).
						SetNumber(p)
				}
				if _, err := client.Port.CreateBulk(builders...).Save(ctx); err != nil {
					log.Printf("Failed to save ports: %v", err)
				}
			}
		}

		log.Println("--- Cycle Complete. Sleeping 1 hour. ---")
		time.Sleep(1 * time.Hour)
	}
}
