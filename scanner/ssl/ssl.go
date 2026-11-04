package ssl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SSLResult represents the minimal information we want to return from a scan.
type SSLResult struct {
	Target      string
	Grade       string
	Status      string // READY, IN_PROGRESS, ERROR, DNS
	CertIssuer  string
	CertSubject string
	CertExpiry  time.Time
	// CertIssues is SSL Labs' issues bitmask of the leaf certificate.
	CertIssues      int
	Protocols       []string
	Vulnerabilities []string
}

// SSLScanner defines the interface for checking SSL configurations. fresh asks
// for a new assessment instead of a cached one (a rescan).
type SSLScanner interface {
	Scan(target string, fresh bool) (*SSLResult, error)
}

// SSLLabsScanner implements SSLScanner using the Qualys SSL Labs API v4.
// It is safe for concurrent use, and one scanner should be shared by every
// worker: it limits how many assessments run at once and how fast new ones
// start, which SSL Labs enforces per email (issue #62).
type SSLLabsScanner struct {
	Email string

	slots *assessmentSlots

	startMu   sync.Mutex
	lastStart time.Time
}

// NewSSLLabsScanner creates a new scanner instance.
// email is required by the SSL Labs API.
func NewSSLLabsScanner(email string) *SSLLabsScanner {
	return &SSLLabsScanner{
		Email: email,
		slots: newAssessmentSlots(defaultMaxAssessments),
	}
}

var (
	apiBaseURL = "https://api.ssllabs.com/api/v4"

	// Timings, variables so tests need not wait.
	pollInterval = 30 * time.Second
	pollTimeout  = 10 * time.Minute
	// overloadBackoff is the wait after SSL Labs answers 429 (too many
	// requests or new assessments too fast) or 529 (service overloaded).
	overloadBackoff = 60 * time.Second
	// newAssessmentCoolOff is the minimum gap between two new assessments.
	newAssessmentCoolOff = 2 * time.Second
)

// overloadAttempts is how many times a request answered 429 or 529 is sent
// before the scan gives up and is stored as a failed check.
const overloadAttempts = 3

// defaultMaxAssessments caps concurrent assessments until SSL Labs reports
// its limit in X-Max-Assessments.
const defaultMaxAssessments = 1

// APIError is a non-200 answer from SSL Labs.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Body)
}

// overloaded reports whether err is SSL Labs asking the client to slow down:
// 429 (rate or new-assessment limit) or 529 (service overloaded).
func overloaded(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) &&
		(apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode == 529)
}

// assessmentSlots limits concurrent assessments. The limit follows SSL Labs'
// X-Max-Assessments header, less what X-Current-Assessments reports running
// beyond our own (another client using the same email, or assessments still
// running from before a restart).
type assessmentSlots struct {
	mu    sync.Mutex
	cond  *sync.Cond
	limit int
	inUse int
}

func newAssessmentSlots(limit int) *assessmentSlots {
	a := &assessmentSlots{limit: limit}
	a.cond = sync.NewCond(&a.mu)
	return a
}

func (a *assessmentSlots) acquire() {
	a.mu.Lock()
	for a.inUse >= a.limit {
		a.cond.Wait()
	}
	a.inUse++
	a.mu.Unlock()
}

func (a *assessmentSlots) release() {
	a.mu.Lock()
	a.inUse--
	a.mu.Unlock()
	a.cond.Broadcast()
}

// update sizes the limit from the headers of an SSL Labs response.
func (a *assessmentSlots) update(h http.Header) {
	maxA, err := strconv.Atoi(h.Get("X-Max-Assessments"))
	if err != nil || maxA <= 0 {
		return
	}
	limit := maxA
	if cur, err := strconv.Atoi(h.Get("X-Current-Assessments")); err == nil {
		a.mu.Lock()
		others := cur - a.inUse
		a.mu.Unlock()
		if others > 0 {
			limit -= others
		}
	}
	a.mu.Lock()
	a.limit = max(1, limit)
	a.mu.Unlock()
	a.cond.Broadcast()
}

// Internal API structs for unmarshalling
// We only define fields we care about or might need for the minimal result

type apiHost struct {
	Host          string        `json:"host"`
	Status        string        `json:"status"`
	StatusMessage string        `json:"statusMessage"`
	StartTime     int64         `json:"startTime"`
	TestTime      int64         `json:"testTime"`
	Endpoints     []apiEndpoint `json:"endpoints"`
	Certs         []apiCert     `json:"certs"`
}

type apiEndpoint struct {
	Grade         string             `json:"grade"`
	Details       apiEndpointDetails `json:"details"`
	StatusMessage string             `json:"statusMessage"`
}

type apiEndpointDetails struct {
	Protocols           []apiProtocol `json:"protocols"`
	Poodle              bool          `json:"poodle"`
	PoodleTls           int           `json:"poodleTls"` // -3 timeout, -2 not supported, -1 failed, 0 unknown, 1 not vuln, 2 vuln
	Heartbleed          bool          `json:"heartbleed"`
	Freak               bool          `json:"freak"`
	Ticketbleed         int           `json:"ticketbleed"` // 1 not vuln, 2 vuln, 3 similar
	VulnBeast           bool          `json:"vulnBeast"`
	OpenSslCcs          int           `json:"openSslCcs"`          // 1 not vuln, 2/3 vuln
	OpenSSLLuckyMinus20 int           `json:"openSSLLuckyMinus20"` // 1 not vuln, 2 vuln
}

type apiProtocol struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type apiCert struct {
	Subject  string `json:"subject"`
	Issuer   string `json:"issuerSubject"` // Note: API doc says issuerSubject
	NotAfter int64  `json:"notAfter"`      // Timestamp
	// Issues is a bitmask of why the certificate isn't trusted: 1 no chain
	// of trust, 2 not yet valid, 4 expired, 8 hostname mismatch, 16
	// revoked, 32 bad common name, 64 self-signed, 128 blacklisted, 256
	// insecure signature, 512 insecure key.
	Issues int `json:"issues"`
}

func (s *SSLLabsScanner) Scan(target string, fresh bool) (*SSLResult, error) {
	// An assessment can run for minutes; hold a slot for all of it.
	s.slots.acquire()
	defer s.slots.release()

	// A rescan must not be answered from the cache, or it would just repeat
	// the old assessment.
	if fresh {
		return s.startAndPoll(target)
	}

	// 1. Check for existing scan first (startNew=false)
	// This helps avoid 529 errors by not triggering new scans unnecessarily.
	hostData, err := s.analyzeRetrying(target, false)

	shouldStartNew := false

	if err != nil {
		// Still told to slow down after backing off: give up for now, the
		// check is retried later.
		if overloaded(err) {
			return nil, err
		}
		// For other errors (e.g. connectivity), we might try to start new or fail.
		// Assuming if fetch failed, we try to start new.
		shouldStartNew = true
	} else {
		// We have some data
		switch hostData.Status {
		case "READY":
			// Check age
			scanTime := time.Unix(hostData.TestTime/1000, 0)
			// If scan is reasonably fresh (e.g. < 24 hours), use it.
			// The user said "if its old, then trigger new scan".
			// 12-24 hours is a typical "fresh" window for SSL Labs.
			if time.Since(scanTime) < 24*time.Hour {
				return s.buildResult(hostData), nil
			}
			// It's old, trigger new
			shouldStartNew = true
		case "IN_PROGRESS", "DNS":
			// Already running, join the poll
			shouldStartNew = false
		default:
			// ERROR or unknown, start new
			shouldStartNew = true
		}
	}

	// 2. Start new scan if needed
	if shouldStartNew {
		return s.startAndPoll(target)
	}
	return s.poll(target, hostData)
}

// startAndPoll asks SSL Labs for a new assessment (startNew=on) and waits for
// it to finish.
func (s *SSLLabsScanner) startAndPoll(target string) (*SSLResult, error) {
	hostData, err := s.analyzeRetrying(target, true)
	if err != nil {
		return nil, err
	}
	return s.poll(target, hostData)
}

// analyzeRetrying is analyze, backing off and trying again while SSL Labs
// answers 429 or 529. New assessments are spaced by newAssessmentCoolOff.
func (s *SSLLabsScanner) analyzeRetrying(host string, startNew bool) (*apiHost, error) {
	var err error
	for attempt := 1; ; attempt++ {
		if startNew {
			s.coolOff()
		}
		var data *apiHost
		data, err = s.analyze(host, startNew)
		if err == nil || !overloaded(err) || attempt == overloadAttempts {
			return data, err
		}
		time.Sleep(time.Duration(attempt) * overloadBackoff)
	}
}

// coolOff waits until newAssessmentCoolOff has passed since the last new
// assessment this scanner started.
func (s *SSLLabsScanner) coolOff() {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if wait := newAssessmentCoolOff - time.Since(s.lastStart); wait > 0 {
		time.Sleep(wait)
	}
	s.lastStart = time.Now()
}

// poll waits until the assessment is READY or ERROR and builds the result.
func (s *SSLLabsScanner) poll(target string, hostData *apiHost) (*SSLResult, error) {
	// 3. Poll until READY or ERROR
	ticker := time.NewTicker(pollInterval) // Slower polling to be polite
	defer ticker.Stop()

	// Hard timeout (SSL Labs can be slow)
	timeout := time.After(pollTimeout)

	for hostData.Status == "IN_PROGRESS" || hostData.Status == "DNS" {
		select {
		case <-timeout:
			return nil, fmt.Errorf("scan timed out")
		case <-ticker.C:
			// Poll without startNew
			next, err := s.analyze(target, false)
			if err != nil {
				// Told to slow down while polling: skip this tick and keep
				// the last state (the old code set hostData to nil here and
				// crashed on the next loop check).
				if overloaded(err) {
					continue
				}
				return nil, err
			}
			hostData = next
		}
	}

	if hostData.Status == "ERROR" {
		return nil, fmt.Errorf("scan failed: %s", hostData.StatusMessage)
	}

	return s.buildResult(hostData), nil
}

func (s *SSLLabsScanner) buildResult(hostData *apiHost) *SSLResult {
	// 4. Construct Result
	result := &SSLResult{
		Target: hostData.Host,
		Status: hostData.Status,
	}

	// We typically take the grade of the first endpoint or the lowest one.
	// SSL Labs usually has multiple endpoints for one host.
	// Let's aggregate.
	if len(hostData.Endpoints) > 0 {
		// Use the first endpoint for the main details for now, or aggregate results.
		ep := hostData.Endpoints[0]
		result.Grade = ep.Grade

		// A host-level "READY" only means the assessment finished, not that the
		// endpoint was reachable/gradeable. When there's no grade, the real
		// reason lives in the endpoint's statusMessage — surface it.
		if ep.Grade == "" && ep.StatusMessage != "" {
			result.Status = ep.StatusMessage
		}

		// Protocols
		var protos []string
		for _, p := range ep.Details.Protocols {
			protos = append(protos, fmt.Sprintf("%s %s", p.Name, p.Version))
		}
		result.Protocols = protos

		// Vulnerabilities
		if ep.Details.Poodle {
			result.Vulnerabilities = append(result.Vulnerabilities, "POODLE (SSLv3)")
		}
		if ep.Details.PoodleTls == 2 {
			result.Vulnerabilities = append(result.Vulnerabilities, "POODLE (TLS)")
		}
		if ep.Details.Heartbleed {
			result.Vulnerabilities = append(result.Vulnerabilities, "Heartbleed")
		}
		if ep.Details.Freak {
			result.Vulnerabilities = append(result.Vulnerabilities, "FREAK")
		}
		if ep.Details.Ticketbleed == 2 {
			result.Vulnerabilities = append(result.Vulnerabilities, "Ticketbleed")
		}
		if ep.Details.VulnBeast {
			result.Vulnerabilities = append(result.Vulnerabilities, "BEAST")
		}
		if ep.Details.OpenSslCcs > 1 {
			result.Vulnerabilities = append(result.Vulnerabilities, "OpenSSL CCS Injection")
		}
		if ep.Details.OpenSSLLuckyMinus20 == 2 {
			result.Vulnerabilities = append(result.Vulnerabilities, "LuckyMinus20")
		}
	}

	// Certs
	if len(hostData.Certs) > 0 {
		cert := hostData.Certs[0] // Leaf cert usually first
		result.CertSubject = cert.Subject
		result.CertIssuer = cert.Issuer
		result.CertExpiry = time.Unix(cert.NotAfter/1000, 0) // API returns ms
		result.CertIssues = cert.Issues
	}

	return result
}

func (s *SSLLabsScanner) analyze(host string, startNew bool) (*apiHost, error) {
	u, err := url.Parse(apiBaseURL + "/analyze")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("host", host)
	q.Set("all", "done") // Get full details
	if startNew {
		q.Set("startNew", "on")
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	// Email is required
	if s.Email == "" {
		return nil, fmt.Errorf("email is required for SSL Labs API")
	}
	req.Header.Set("email", s.Email)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	s.slots.update(resp.Header)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}

	var data apiHost
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return &data, nil
}

// RegisterRequest represents the payload for the registration API.
type RegisterRequest struct {
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	Email        string `json:"email"`
	Organization string `json:"organization"`
}

// ErrorResponse represents the error structure from the API.
type ErrorResponse struct {
	Errors []struct {
		Field   string `json:"field"`
		Message string `json:"message"`
	} `json:"errors"`
}

// Register registers the user with the SSL Labs API.
func Register(firstName, lastName, email, organization string) error {
	reqData := RegisterRequest{
		FirstName:    firstName,
		LastName:     lastName,
		Email:        email,
		Organization: organization,
	}

	jsonData, err := json.Marshal(reqData)
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %w", err)
	}

	resp, err := http.Post(apiBaseURL+"/register", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send registration request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read registration response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.Unmarshal(body, &errorResponse); err == nil && len(errorResponse.Errors) > 0 {
			// Construct a readable error message
			var msgs []string
			for _, e := range errorResponse.Errors {
				if strings.Contains(e.Message, "already registered") {
					return nil // User is already registered, treat as success
				}
				msgs = append(msgs, fmt.Sprintf("%s: %s", e.Field, e.Message))
			}
			return fmt.Errorf("registration failed: %s", strings.Join(msgs, ", "))
		}
		return fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Success
	return nil
}
