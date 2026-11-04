package ports

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ScannerConfig holds the knobs you can turn.
type ScannerConfig struct {
	Timeout     time.Duration
	Concurrency int // Max number of simultaneous connections (Semaphore)
	Retries     int
	Ports       []int // what Scan probes, from ParsePorts
}

// SimpleScanner implements your PortScanner interface.
type SimpleScanner struct {
	config ScannerConfig
}

// ErrUnreachable is returned by Scan when the host gave no answer at all:
// no port is open and no port refused a connection, so every dial failed
// (timeout or no route). An unreachable host is not "clean" (issue #29).
var ErrUnreachable = errors.New("host unreachable")

// portState is the outcome of probing one port.
type portState int

const (
	stateOpen        portState = iota // connected
	stateClosed                       // connection refused: the host answered
	stateFiltered                     // timeout: a firewall may be dropping packets
	stateUnreachable                  // no route to the host at all
)

// NewSimpleScanner creates a scanner with safe defaults.
func NewSimpleScanner(ms, concurrency, retries int, ports []int) *SimpleScanner {
	return &SimpleScanner{
		config: ScannerConfig{
			Timeout:     time.Duration(ms) * time.Millisecond,
			Concurrency: concurrency,
			Retries:     retries,
			Ports:       ports,
		},
	}
}

// Scan performs a concurrent TCP Connect scan. It returns the open ports and
// a nil error for a reachable host, open or closed; a host where no port is
// open and no port refused a connection (all dials failed) returns a nil
// slice and an error wrapping ErrUnreachable with the no-route reason when
// one was seen, otherwise "no response on any port".
func (s *SimpleScanner) Scan(target string) ([]int, error) {
	var (
		openPorts      []int
		closed         bool
		unreachableErr error
		mutex          sync.Mutex
		wg             sync.WaitGroup
	)

	// 1. Semaphore: Create a buffered channel to limit concurrency.
	// This prevents "too many open files" errors on limited systems.
	sem := make(chan struct{}, s.config.Concurrency)

	for _, port := range s.config.Ports {
		// Acquire token
		sem <- struct{}{}
		wg.Add(1)

		go func(p int) {
			defer func() {
				<-sem // Release token
				wg.Done()
			}()

			// Retry only filtered (timeout) outcomes: closed and
			// unreachable are final, and sleeping between retries only
			// stretched the scan without changing the outcome.
			for attempt := 0; ; attempt++ {
				st, err := s.probe(target, p)
				if st == stateOpen {
					mutex.Lock()
					openPorts = append(openPorts, p)
					mutex.Unlock()
					return
				}
				if st != stateFiltered || attempt+1 >= s.config.Retries {
					mutex.Lock()
					if st == stateClosed {
						closed = true
					}
					if st == stateUnreachable && unreachableErr == nil {
						unreachableErr = err
					}
					mutex.Unlock()
					return
				}
			}
		}(port)
	}

	wg.Wait()

	sort.Ints(openPorts)
	if err := scanError(len(openPorts), closed, unreachableErr); err != nil {
		return nil, err
	}
	return openPorts, nil
}

// scanError is the Scan result for a host where no port is open and no port
// was refused: every dial failed, so the host is unreachable (issue #29).
// A probe's no-route reason is wrapped when one was seen; otherwise a
// generic reason is used (the host may simply be dead).
func scanError(open int, closed bool, firstUnreachable error) error {
	if open > 0 || closed {
		return nil
	}
	if firstUnreachable != nil {
		return fmt.Errorf("%w: %v", ErrUnreachable, firstUnreachable)
	}
	return fmt.Errorf("%w: no response on any port", ErrUnreachable)
}

// Confirm re-probes the given ports of target, up to 3 tries each (retrying
// only filtered outcomes), and returns the sorted ports that are open. It is
// the flap check: a port the scan gained or lost against the previous result
// has to answer again before the change is saved (issue #29).
func (s *SimpleScanner) Confirm(target string, ports []int) []int {
	var out []int
	for _, p := range ports {
		for attempt := 0; attempt < 3; attempt++ {
			st, _ := s.probe(target, p)
			if st == stateOpen {
				out = append(out, p)
				break
			}
			if st != stateFiltered {
				break
			}
		}
	}
	sort.Ints(out)
	return out
}

// probe dials one port and classifies the outcome. The error is non-nil for
// every state except stateOpen; callers wanting the reason (Scan) record the
// first unreachable one.
func (s *SimpleScanner) probe(target string, port int) (portState, error) {
	address := net.JoinHostPort(target, fmt.Sprintf("%d", port))

	// Use net.DialTimeout for full TCP handshake (Connect Scan)
	conn, err := net.DialTimeout("tcp", address, s.config.Timeout)
	if err != nil {
		return classifyDialError(err), err
	}

	// Connection succeeded! Close it immediately.
	conn.Close()
	return stateOpen, nil
}

// classifyDialError maps a dial error onto a port state. Anything that is
// not a timeout or a route error means the host (or its firewall) answered,
// so it counts as closed.
func classifyDialError(err error) portState {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return stateClosed
	case errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.EADDRNOTAVAIL),
		strings.Contains(err.Error(), "no route to host"):
		return stateUnreachable
	default:
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return stateFiltered
		}
		return stateClosed
	}
}
