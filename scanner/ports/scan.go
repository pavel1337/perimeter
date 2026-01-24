package ports

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	portMin = 1
	portMax = 65535
)

// ScannerConfig holds the knobs you can turn.
type ScannerConfig struct {
	Timeout     time.Duration
	Concurrency int // Max number of simultaneous connections (Semaphore)
	Retries     int
}

// SimpleScanner implements your PortScanner interface.
type SimpleScanner struct {
	config ScannerConfig
}

// NewSimpleScanner creates a scanner with safe defaults.
func NewSimpleScanner(ms, concurrency, retries int) *SimpleScanner {
	return &SimpleScanner{
		config: ScannerConfig{
			Timeout:     time.Duration(ms) * time.Millisecond,
			Concurrency: concurrency,
			Retries:     retries,
		},
	}
}

// Scan performs a concurrent TCP Connect scan.
func (s *SimpleScanner) Scan(target string) ([]int, error) {
	var (
		openPorts []int
		mutex     sync.Mutex
		wg        sync.WaitGroup
	)

	// 1. Semaphore: Create a buffered channel to limit concurrency.
	// This prevents "too many open files" errors on limited systems.
	sem := make(chan struct{}, s.config.Concurrency)

	for port := portMin; port <= portMax; port++ {
		// Acquire token
		sem <- struct{}{}
		wg.Add(1)

		go func(p int) {
			defer func() {
				<-sem // Release token
				wg.Done()
			}()

			for i := 0; i < s.config.Retries; i++ {
				if s.isOpen(target, p) {
					mutex.Lock()
					openPorts = append(openPorts, p)
					mutex.Unlock()
					break
				} else {
					// Wait before retrying
					time.Sleep(s.config.Timeout)
				}
			}
		}(port)
	}

	wg.Wait()

	// Sort results for cleaner output
	sort.Ints(openPorts)

	return openPorts, nil
}

// isOpen tries to establish a TCP connection.
func (s *SimpleScanner) isOpen(target string, port int) bool {
	address := net.JoinHostPort(target, fmt.Sprintf("%d", port))

	// Use net.DialTimeout for full TCP handshake (Connect Scan)
	conn, err := net.DialTimeout("tcp", address, s.config.Timeout)
	if err != nil {
		// Connection failed (Closed or Filtered)
		return false
	}

	// Connection succeeded! Close it immediately.
	conn.Close()
	return true
}
