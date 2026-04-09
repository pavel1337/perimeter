package main

import (
	"bufio"
	"context"
	"embed"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"perimeter/ent"
	"perimeter/internal/scanner"
	"perimeter/internal/server"
	"perimeter/internal/storage"
	"perimeter/scanner/ssl"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed views/*
var viewsfs embed.FS

func getEnvOrDefaultStr(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvOrDefaultDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getEnvOrDefaultInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

var (
	targetFile   = getEnvOrDefaultStr("TARGET_FILE", "")
	httpPort     = getEnvOrDefaultStr("HTTP_PORT", "3000")
	firstName    = getEnvOrDefaultStr("FIRST_NAME", "")
	lastName     = getEnvOrDefaultStr("LAST_NAME", "")
	email        = getEnvOrDefaultStr("EMAIL", "")
	organization = getEnvOrDefaultStr("ORGANIZATION", "")
	dbPath       = getEnvOrDefaultStr("DB_PATH", "perimeter.db")
	dbDriver     = getEnvOrDefaultStr("DB_DRIVER", "sqlite3")
	dbDSN        = getEnvOrDefaultStr("DB_DSN", "")
	workerCount  = getEnvOrDefaultInt("WORKER_COUNT", 3)

	portInterval = getEnvOrDefaultDuration("PORT_INTERVAL", 1*time.Hour)
	sslInterval  = getEnvOrDefaultDuration("SSL_INTERVAL", 12*time.Hour)
	cspInterval  = getEnvOrDefaultDuration("CSP_INTERVAL", 1*time.Hour)
)

func main() {
	// 1. Parse CLI Flags
	flag.StringVar(&targetFile, "targets", targetFile, "Path to text file containing targets (one per line)")
	flag.StringVar(&httpPort, "port", httpPort, "HTTP listen port")
	flag.StringVar(&firstName, "firstName", firstName, "First name for SSL Labs")
	flag.StringVar(&lastName, "lastName", lastName, "Last name for SSL Labs")
	flag.StringVar(&email, "email", email, "Email for SSL Labs")
	flag.StringVar(&organization, "organization", organization, "Organization for SSL Labs")
	flag.StringVar(&dbPath, "db", dbPath, "Path to SQLite database")
	flag.StringVar(&dbDriver, "dbDriver", dbDriver, "Database driver: sqlite3 or postgres")
	flag.StringVar(&dbDSN, "dbDSN", dbDSN, "PostgreSQL DSN (required when dbDriver=postgres)")
	flag.IntVar(&workerCount, "workers", workerCount, "Number of concurrent workers")

	// Scanning intervals
	flag.DurationVar(&portInterval, "portInterval", portInterval, "Interval for port scans")
	flag.DurationVar(&sslInterval, "sslInterval", sslInterval, "Interval for SSL scans")
	flag.DurationVar(&cspInterval, "cspInterval", cspInterval, "Interval for CSP scans")

	flag.Parse()

	// SSL Labs Registration
	if firstName != "" && lastName != "" && email != "" && organization != "" {
		log.Println("Registering with SSL Labs...")
		if err := ssl.Register(firstName, lastName, email, organization); err != nil {
			log.Printf("Warning: Failed to register with SSL Labs: %v", err)
			// Proceeding, as they might be already registered or we just want to run other scans
		} else {
			log.Println("Registration successful.")
		}
	} else if email != "" {
		// Just email provided, assume registered
	} else {
		// Only fatal if we assume SSL scanning is strictly required
		log.Println("Warning: SSL Labs details missing. SSL scanning might be limited or fail.")
	}

	// 2. Initialize Database & Storage
	var (
		client *ent.Client
		err    error
	)
	switch dbDriver {
	case "sqlite3":
		client, err = ent.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&_fk=1", dbPath))
	case "postgres":
		if dbDSN == "" {
			log.Fatal("DB_DSN is required when DB_DRIVER=postgres")
		}
		client, err = ent.Open("postgres", dbDSN)
	default:
		log.Fatalf("unsupported DB_DRIVER: %s (use sqlite3 or postgres)", dbDriver)
	}
	if err != nil {
		log.Fatalf("failed opening database connection: %v", err)
	}
	log.Printf("Database: %s", dbDriver)
	defer client.Close()

	// Auto-Migration
	if err := client.Schema.Create(context.Background()); err != nil {
		log.Fatalf("failed creating schema resources: %v", err)
	}

	store := storage.NewEntStorage(client)

	// 3. Import Targets if provided
	if targetFile != "" {
		ctx := context.Background()
		lines, err := readLines(targetFile)
		if err != nil {
			log.Fatalf("Failed to read target file: %v", err)
		}

		count, err := store.ImportTargets(ctx, lines)
		if err != nil {
			log.Printf("Error importing targets: %v", err)
		} else {
			log.Printf("Imported/Checked %d targets from %s", count, targetFile)
		}
	} else {
		// Only warning, maybe they rely on existing DB
		log.Println("No target file provided, using existing database targets.")
	}

	// 4. Start Scanners
	scanConfig := scanner.ScannerConfig{
		PortScanInterval: portInterval,
		SSLScanInterval:  sslInterval,
		CSPScanInterval:  cspInterval,
		SSLEmail:         email,
		WorkerCount:      workerCount,
	}

	mgr := scanner.NewManager(store, scanConfig)
	mgr.Start()

	// 5. Start Web Server
	srv := server.New(store, viewsfs)
	log.Printf("Perimeter is running on http://localhost:%s", httpPort)
	log.Fatal(srv.Listen(":" + httpPort))
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
