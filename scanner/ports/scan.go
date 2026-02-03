package ports

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// ScannerConfig holds the knobs you can turn.
type ScannerConfig struct {
	Timeout     time.Duration
	Concurrency int // Max number of simultaneous connections (Semaphore)
	Retries     int
	PortMin     int
	PortMax     int
}

// SimpleScanner implements your PortScanner interface.
type SimpleScanner struct {
	config ScannerConfig
}

// NewSimpleScanner creates a scanner with safe defaults.
func NewSimpleScanner(ms, concurrency, retries int, portMin, portMax int) *SimpleScanner {
	return &SimpleScanner{
		config: ScannerConfig{
			Timeout:     time.Duration(ms) * time.Millisecond,
			Concurrency: concurrency,
			Retries:     retries,
			PortMin:     portMin,
			PortMax:     portMax,
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

	for port := s.config.PortMin; port <= s.config.PortMax; port++ {
		// Acquire token
		sem <- struct{}{}
		wg.Add(1)

		go func(p int) {
			defer func() {
				<-sem // Release token
				wg.Done()
			}()

			for range s.config.Retries {
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
