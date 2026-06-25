package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type GandiConfig struct {
	APIKey string `json:"api_key"`
}

type GandiSource struct {
	config GandiConfig
	client *http.Client
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
			config: cfg,
			client: &http.Client{Timeout: 30 * time.Second},
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

	return targets, nil
}

func (s *GandiSource) fetchDomains(ctx context.Context) ([]string, error) {
	var allDomains []string
	page := 1
	perPage := 100

	for {
		url := fmt.Sprintf("https://api.gandi.net/v5/domain/domains?page=%d&per_page=%d", page, perPage)
		body, err := s.doRequest(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetch domains: %w", err)
		}

		var domains []gandiDomain
		if err := json.Unmarshal(body, &domains); err != nil {
			return nil, fmt.Errorf("parse domains: %w", err)
		}

		for _, d := range domains {
			allDomains = append(allDomains, d.FQDN)
		}

		if len(domains) < perPage {
			break
		}
		page++
	}

	return allDomains, nil
}

func (s *GandiSource) fetchRecords(ctx context.Context, domain string) ([]gandiRecord, error) {
	url := fmt.Sprintf("https://api.gandi.net/v5/livedns/domains/%s/records", domain)
	body, err := s.doRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	var records []gandiRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func (s *GandiSource) doRequest(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.config.APIKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("gandi API returned %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}
