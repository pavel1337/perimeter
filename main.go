package main

import (
	"bufio"
	"context"
	"embed"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	_ "github.com/mattn/go-sqlite3"

	"perimeter/ent"
	"perimeter/ent/target"
	"perimeter/scanner/csp"
	"perimeter/scanner/ports"
	"perimeter/scanner/ssl"
)

//go:embed views/*
var viewsfs embed.FS

func main() {
	// 1. Parse CLI Flags
	targetFile := flag.String("targets", "", "Path to text file containing targets (one per line)")
	httpPort := flag.String("port", "3000", "HTTP listen port")
	firstName := flag.String("firstName", "", "First name for SSL Labs")
	lastName := flag.String("lastName", "", "Last name for SSL Labs")
	email := flag.String("email", "", "Email for SSL Labs")
	organization := flag.String("organization", "", "Organization for SSL Labs")
	flag.Parse()

	if *targetFile == "" {
		log.Fatal("Error: You must provide a target list. Usage: ./perimeter -targets=hosts.txt ...")
	}

	// SSL Labs Registration is mandatory for this app now
	if *firstName == "" || *lastName == "" || *email == "" || *organization == "" {
		log.Fatal("Error: SSL Labs registration requires -firstName, -lastName, -email, and -organization flags.")
	}

	log.Println("Registering with SSL Labs...")
	if err := ssl.Register(*firstName, *lastName, *email, *organization); err != nil {
		log.Fatalf("Failed to register with SSL Labs: %v", err)
	}
	log.Println("Registration successful.")

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

	// 4. Start the Scanner Loops (Background Workers)
	// We pass the client so it can save results
	go runPortScanLoop(client)
	go runCSPScanLoop(client)
	go runSSLScanLoop(client, *email)

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
				// Ideally we order by desc time and limit 1, but we do this in view for simplicity or slice Logic
			}).
			WithSslScans().
			WithCspScans().
			All(c.Context())

		if err != nil {
			return c.Status(500).SendString(err.Error())
		}

		for _, t := range targets {
			for _, s := range t.Edges.Scans {
				fmt.Printf("Target: %s, Scan: %s, Ports: %v\n", t.Input, s.ScannedAt, s.Edges.Ports)
			}
		}

		return c.Render("views/index", fiber.Map{
			"Title":   "Perimeter Dashboard",
			"Targets": targets,
		}, "views/layouts/main")
	})

	app.Get("/targets/:id", func(c *fiber.Ctx) error {
		idStr := c.Params("id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return c.Status(400).SendString("Invalid ID")
		}

		target, err := client.Target.Query().
			Where(target.ID(id)).
			WithScans(func(q *ent.PortScanQuery) {
				q.WithPorts()
			}).
			WithSslScans().
			WithCspScans().
			Only(c.Context())

		if err != nil {
			return c.Status(404).SendString("Target not found")
		}

		return c.Render("views/target", fiber.Map{
			"Title":  "Target Details",
			"Target": target,
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
// Helper: The Port Scanner Loop
// ---------------------------------------------------------
func runPortScanLoop(client *ent.Client) {
	// Scanner Config: 500ms timeout, 100 concurrent threads
	portScanner := ports.NewSimpleScanner(1000, 100, 3)
	ctx := context.Background()

	for {
		log.Println("--- Starting Port Scan Cycle ---")

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

			log.Printf("Scanning Ports for %s...", t.Input)

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

		log.Println("--- Port Cycle Complete. Sleeping 1 hour. ---")
		time.Sleep(1 * time.Hour)
	}
}

// ---------------------------------------------------------
// Helper: The SSL Scanner Loop
// ---------------------------------------------------------
func runSSLScanLoop(client *ent.Client, email string) {
	sslScanner := ssl.NewSSLLabsScanner(email)
	ctx := context.Background()

	for {
		log.Println("--- Starting SSL Scan Cycle ---")

		// 1. Get all targets
		targets, err := client.Target.Query().WithSslScans().All(ctx)
		if err != nil {
			log.Printf("DB Error: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		for _, t := range targets {
			// Filter: Only Hostnames
			if !isHostname(t.Input) {
				continue
			}

			// Check if target had recent scans
			if len(t.Edges.SslScans) > 0 {
				lastScan := t.Edges.SslScans[0]
				if time.Since(lastScan.ScannedAt) < 12*time.Hour { // SSL Labs is slower/stricter, lets do 12h
					continue
				}
			}

			log.Printf("Scanning SSL for %s... (this may take a minute)", t.Input)

			// 2. Perform Scan
			result, err := sslScanner.Scan(t.Input)
			if err != nil {
				log.Printf("Failed to SSL scan %s: %v", t.Input, err)
				continue
			}

			// 3. Save History
			_, err = client.SSLScan.Create().
				SetTarget(t).
				SetScannedAt(time.Now()).
				SetGrade(result.Grade).
				SetStatus(result.Status).
				SetCertIssuer(result.CertIssuer).
				SetCertSubject(result.CertSubject).
				SetCertExpiry(result.CertExpiry).
				SetProtocols(result.Protocols).
				SetVulnerabilities(result.Vulnerabilities).
				Save(ctx)

			if err != nil {
				log.Printf("Failed to save SSL scan record: %v", err)
			}
		}

		log.Println("--- SSL Cycle Complete. Sleeping 1 hour (checking loop). ---")
		time.Sleep(1 * time.Hour)
	}
}

// ---------------------------------------------------------
// Helper: The CSP Scanner Loop
// ---------------------------------------------------------
func runCSPScanLoop(client *ent.Client) {
	evaluator := csp.NewEvaluator()
	ctx := context.Background()

	for {
		log.Println("--- Starting CSP Scan Cycle ---")
		targets, err := client.Target.Query().WithCspScans().All(ctx)
		if err != nil {
			log.Printf("DB Error: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		for _, t := range targets {
			if !isHostname(t.Input) {
				continue
			}

			// Debounce
			if len(t.Edges.CspScans) > 0 {
				lastScan := t.Edges.CspScans[0]
				if time.Since(lastScan.ScannedAt) < 1*time.Hour {
					continue
				}
			}

			log.Printf("Scanning CSP for %s...", t.Input)
			// Fetch CSP Header
			// We try HTTPS first, then HTTP
			// Timeout 5s
			clientHttp := http.Client{
				Timeout: 5 * time.Second,
			}

			var cspHeader string
			resp, err := clientHttp.Head("https://" + t.Input)
			if err != nil {
				// Try HTTP
				resp, err = clientHttp.Head("http://" + t.Input)
			}

			var findings []csp.Finding

			if err != nil {
				log.Printf("Failed to connect to %s: %v", t.Input, err)
				// We still might want to save a record indicating failure, but for now we skip?
				// Or we create a finding saying "Unreachable"?
				// The prompt says "handle absence of csp, it must be marked as a security issue".
				// If unreachable, we probably can't say much about CSP.
				continue
			} else {
				defer resp.Body.Close()
				cspHeader = resp.Header.Get("Content-Security-Policy")

				if cspHeader == "" {
					// Absence of CSP Finding
					findings = append(findings, csp.Finding{
						Type:        csp.TypeMissingDirectives, // Reuse generic missing directives type
						Description: "No Content-Security-Policy header found.",
						Severity:    csp.SeverityHigh,
						Directive:   "Header",
					})
				} else {
					// Evaluate
					f, err := evaluator.Evaluate(cspHeader)
					if err != nil {
						log.Printf("Error evaluating CSP for %s: %v", t.Input, err)
					}
					findings = append(findings, f...)
				}
			}

			// Save
			_, err = client.CSPScan.Create().
				SetTarget(t).
				SetScannedAt(time.Now()).
				SetCspHeader(cspHeader).
				SetFindings(findings).
				Save(ctx)

			if err != nil {
				log.Printf("Failed to save CSP scan: %v", err)
			}
		}

		log.Println("--- CSP Cycle Complete. Sleeping 1 hour. ---")
		time.Sleep(1 * time.Hour)
	}
}

func isHostname(input string) bool {
	return net.ParseIP(input) == nil
}
