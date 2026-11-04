package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// gandiAPI is the Gandi v5 API root. A field on GandiSource so tests can
// point it at a fake server.
const gandiAPI = "https://api.gandi.net/v5"

// gandiPerPage is the page size asked for on paged endpoints.
const gandiPerPage = 100

type GandiConfig struct {
	APIKey string `json:"api_key"`
}

type GandiSource struct {
	config  GandiConfig
	client  *http.Client
	baseURL string
}

func NewGandiFactory() Factory {
	return func(config json.RawMessage) (Source, error) {
		var cfg GandiConfig
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, fmt.Errorf("invalid gandi config: %w", err)
		}
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("gandi: api_key is required")
		}
		return &GandiSource{
			config:  cfg,
			client:  &http.Client{Timeout: 30 * time.Second},
			baseURL: gandiAPI,
		}, nil
	}
}

func (s *GandiSource) Name() string {
	return "gandi"
}

type gandiDomain struct {
	FQDN string `json:"fqdn"`
}

type gandiRecord struct {
	Name   string   `json:"rrset_name"`
	Type   string   `json:"rrset_type"`
	Values []string `json:"rrset_values"`
}

func (s *GandiSource) Fetch(ctx context.Context) ([]string, error) {
	seen := make(map[string]bool)
	var targets []string
	var failed ZoneErrors

	// Fetch all domains
	domains, err := s.fetchDomains(ctx)
	if err != nil {
		return nil, err
	}

	for _, domain := range domains {
		if !seen[domain] {
			seen[domain] = true
			targets = append(targets, domain)
		}

		// Fetch DNS records to discover subdomains
		records, err := s.fetchRecords(ctx, domain)
		if err != nil {
			failed.add(domain, err)
			continue
		}

		for _, r := range records {
			if r.Type != "A" && r.Type != "AAAA" && r.Type != "CNAME" {
				continue
			}
			if r.Name == "@" || r.Name == "" {
				continue
			}
			fqdn := r.Name + "." + domain
			if !seen[fqdn] {
				seen[fqdn] = true
				targets = append(targets, fqdn)
			}
		}
	}

	return targets, failed.orNil()
}

func (s *GandiSource) fetchDomains(ctx context.Context) ([]string, error) {
	domains, err := fetchAllPages[gandiDomain](ctx, s, s.baseURL+"/domain/domains")
	if err != nil {
		return nil, fmt.Errorf("fetch domains: %w", err)
	}
	fqdns := make([]string, 0, len(domains))
	for _, d := range domains {
		fqdns = append(fqdns, d.FQDN)
	}
	return fqdns, nil
}

// fetchRecords reads every page of a zone's records. Gandi pages them sorted
// by name, so stopping after the first page drops the end of the alphabet
// (issue #60).
func (s *GandiSource) fetchRecords(ctx context.Context, domain string) ([]gandiRecord, error) {
	return fetchAllPages[gandiRecord](ctx, s, s.baseURL+"/livedns/domains/"+domain+"/records")
}

// fetchAllPages GETs endpoint page by page until Total-Count items have been
// read or a page comes back short.
func fetchAllPages[T any](ctx context.Context, s *GandiSource, endpoint string) ([]T, error) {
	var all []T
	for page := 1; ; page++ {
		url := fmt.Sprintf("%s?page=%d&per_page=%d", endpoint, page, gandiPerPage)
		body, header, err := s.doRequest(ctx, url)
		if err != nil {
			return nil, err
		}
		var items []T
		if err := json.Unmarshal(body, &items); err != nil {
			return nil, fmt.Errorf("parse %s: %w", endpoint, err)
		}
		all = append(all, items...)

		if len(items) < gandiPerPage {
			return all, nil
		}
		if total, err := strconv.Atoi(header.Get("Total-Count")); err == nil && len(all) >= total {
			return all, nil
		}
	}
}

func (s *GandiSource) doRequest(ctx context.Context, url string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.config.APIKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("gandi API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	return body, resp.Header, err
}
