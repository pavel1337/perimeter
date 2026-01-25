package ssl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SSLResult represents the minimal information we want to return from a scan.
type SSLResult struct {
	Target          string
	Grade           string
	Status          string // READY, IN_PROGRESS, ERROR, DNS
	CertIssuer      string
	CertSubject     string
	CertExpiry      time.Time
	Protocols       []string
	Vulnerabilities []string
}

// SSLScanner defines the interface for checking SSL configurations.
type SSLScanner interface {
	Scan(target string) (*SSLResult, error)
}

// SSLLabsScanner implements SSLScanner using the Qualys SSL Labs API v4.
type SSLLabsScanner struct {
	Email string
}

// NewSSLLabsScanner creates a new scanner instance.
// email is required by the SSL Labs API.
func NewSSLLabsScanner(email string) *SSLLabsScanner {
	return &SSLLabsScanner{
		Email: email,
	}
}

var (
	apiBaseURL = "https://api.ssllabs.com/api/v4"
)

// Internal API structs for unmarshalling
// We only define fields we care about or might need for the minimal result

type apiHost struct {
	Host          string        `json:"host"`
	Status        string        `json:"status"`
	StatusMessage string        `json:"statusMessage"`
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
}

func (s *SSLLabsScanner) Scan(target string) (*SSLResult, error) {
	// 1. Check Info / Availability (Optional but good practice, skipping for minimalism unless 429)

	// 2. Invoke analyze with startNew=on & all=done
	// Note: startNew should only be used once. If we want to poll, we drop it.
	// For simplicity, we'll try to get a cached one or start new.
	// Actually, the docs say: "Invoke analyze with the startNew parameter to on. Set all to done."

	// Initial call to start or retrieve status
	hostData, err := s.analyze(target, true)
	if err != nil {
		return nil, err
	}

	// 3. Poll until READY or ERROR
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Hard timeout of 5 minutes roughly
	timeout := time.After(5 * time.Minute)

	for hostData.Status == "IN_PROGRESS" || hostData.Status == "DNS" {
		select {
		case <-timeout:
			return nil, fmt.Errorf("scan timed out")
		case <-ticker.C:
			// Poll without startNew
			hostData, err = s.analyze(target, false)
			if err != nil {
				return nil, err
			}
		}
	}

	if hostData.Status == "ERROR" {
		return nil, fmt.Errorf("scan failed: %s", hostData.StatusMessage)
	}

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
		cert := hostData.Certs[0] // Leaf cert usually first? Doc check: "chain certificates in the order in which they were retrieved". Usually leaf is first.
		result.CertSubject = cert.Subject
		result.CertIssuer = cert.Issuer
		result.CertExpiry = time.Unix(cert.NotAfter/1000, 0) // API returns ms
	}

	return result, nil
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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
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
