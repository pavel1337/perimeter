package ports

import (
	"errors"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func listenPort(t *testing.T) (int, net.Listener) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	return port, l
}

// closedPort returns a port that just had a listener on it.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return port
}

func newTestScanner(min, max int) *SimpleScanner {
	var ports []int
	for p := min; p <= max; p++ {
		ports = append(ports, p)
	}
	return NewSimpleScanner(500, 10, 2, ports)
}

func TestScanFindsOpenPorts(t *testing.T) {
	p1, l1 := listenPort(t)
	defer l1.Close()
	p2, l2 := listenPort(t)
	defer l2.Close()
	min, max := p1, p2
	if min > max {
		min, max = max, min
	}

	s := newTestScanner(min, max)
	ports, err := s.Scan("127.0.0.1")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// Other processes may listen on 127.0.0.1 inside the range, so check
	// the invariants instead of the exact set.
	if !slices.Contains(ports, p1) || !slices.Contains(ports, p2) {
		t.Errorf("Scan = %v, want it to contain %d and %d", ports, p1, p2)
	}
	if !slices.IsSorted(ports) {
		t.Errorf("Scan = %v, want sorted ports", ports)
	}
	for _, p := range ports {
		if p < min || p > max {
			t.Errorf("Scan reported port %d outside the range [%d, %d]", p, min, max)
		}
	}
}

func TestScanClosedPortIsNotUnreachable(t *testing.T) {
	p := closedPort(t)
	s := newTestScanner(p, p)
	ports, err := s.Scan("127.0.0.1")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(ports) != 0 {
		t.Errorf("Scan = %v, want no open ports", ports)
	}
}

func TestConfirmKeepsOpenDropsClosed(t *testing.T) {
	p, l := listenPort(t)
	defer l.Close()
	closed := closedPort(t)

	s := newTestScanner(p, p)
	got := s.Confirm("127.0.0.1", []int{closed, p})
	if !slices.Equal(got, []int{p}) {
		t.Errorf("Confirm = %v, want [%d]", got, p)
	}
}

// fakeTimeout is a net.Error that reports Timeout, like a real dial timeout.
type fakeTimeout struct{ err error }

func (e *fakeTimeout) Error() string   { return e.err.Error() }
func (e *fakeTimeout) Timeout() bool   { return true }
func (e *fakeTimeout) Temporary() bool { return true }

func TestClassifyDialError(t *testing.T) {
	opErr := func(err error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: err}
	}
	cases := []struct {
		name string
		err  error
		want portState
	}{
		{"refused", opErr(os.NewSyscallError("connect", syscall.ECONNREFUSED)), stateClosed},
		{"net unreachable", opErr(os.NewSyscallError("connect", syscall.ENETUNREACH)), stateUnreachable},
		{"host unreachable", opErr(os.NewSyscallError("connect", syscall.EHOSTUNREACH)), stateUnreachable},
		{"no local address", opErr(os.NewSyscallError("connect", syscall.EADDRNOTAVAIL)), stateUnreachable},
		{"no route string", errors.New("dial tcp 192.0.2.1:80: connect: no route to host"), stateUnreachable},
		{"deadline", opErr(os.ErrDeadlineExceeded), stateFiltered},
		{"timeout net.Error", &fakeTimeout{err: errors.New("i/o timeout")}, stateFiltered},
		{"reset", opErr(os.NewSyscallError("connect", syscall.ECONNRESET)), stateClosed},
		{"other", errors.New("weird failure"), stateClosed},
	}
	for _, tc := range cases {
		if got := classifyDialError(tc.err); got != tc.want {
			t.Errorf("%s: classifyDialError(%v) = %d, want %d", tc.name, tc.err, got, tc.want)
		}
	}
}

// The unreachable decision is pure: no port open and no port refused means
// the host gave no answer at all, whether the probes timed out or saw no
// route.
func TestScanErrorDecision(t *testing.T) {
	noRoute := errors.New("dial tcp 192.0.2.1:80: connect: no route to host")
	cases := []struct {
		name        string
		open        int
		closed      bool
		unreachable error
		wantErr     bool
		wantReason  string
	}{
		{"all filtered", 0, false, nil, true, "no response on any port"},
		{"filtered and closed", 0, true, nil, false, ""},
		{"unreachable only", 0, false, noRoute, true, "no route to host"},
		{"unreachable and closed", 0, true, noRoute, false, ""},
		{"open and unreachable", 2, false, noRoute, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := scanError(tc.open, tc.closed, tc.unreachable)
			if (err != nil) != tc.wantErr {
				t.Fatalf("scanError = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				if !errors.Is(err, ErrUnreachable) {
					t.Fatalf("err %v does not wrap ErrUnreachable", err)
				}
				if !strings.Contains(err.Error(), tc.wantReason) {
					t.Fatalf("err %v lacks reason %q", err, tc.wantReason)
				}
			}
		})
	}
}
