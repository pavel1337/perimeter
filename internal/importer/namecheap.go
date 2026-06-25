package importer

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"time"
)

type NamecheapConfig struct {
	APIUser  string `json:"api_user"`
	APIKey   string `json:"api_key"`
	ClientIP string `json:"client_ip"`
}

type NamecheapSource struct {
	config NamecheapConfig
	client *http.Client
}

func NewNamecheapFactory() Factory {
	return func(config json.RawMessage) (Source, error) {
		var cfg NamecheapConfig
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, fmt.Errorf("invalid namecheap config: %w", err)
		}
		if cfg.APIUser == "" || cfg.APIKey == "" || cfg.ClientIP == "" {
			return nil, fmt.Errorf("namecheap: api_user, api_key, and client_ip are required")
		}
		return &NamecheapSource{
			config: cfg,
			client: &http.Client{Timeout: 30 * time.Second},
		}, nil
	}
}

func (s *NamecheapSource) Name() string {
	return "namecheap"
}

type ncDomainsResponse struct {
	XMLName xml.Name `xml:"ApiResponse"`
	Errors  struct {
		Error []struct {
			Number  string `xml:"Number,attr"`
			Message string `xml:",chardata"`
		} `xml:"Error"`
	} `xml:"Errors"`
	CommandResponse struct {
		DomainGetListResult struct {
			Domains []struct {
				Name string `xml:"Name,attr"`
			} `xml:"Domain"`
		} `xml:"DomainGetListResult"`
		Paging struct {
			TotalItems int `xml:"TotalItems"`
			PageSize   int `xml:"PageSize"`
		} `xml:"Paging"`
	} `xml:"CommandResponse"`
}

type ncHostsResponse struct {
	XMLName         xml.Name `xml:"ApiResponse"`
	CommandResponse struct {
		DomainDNSGetHostsResult struct {
			Hosts []struct {
				Name string `xml:"Name,attr"`
				Type string `xml:"Type,attr"`
			} `xml:"host"`
		} `xml:"DomainDNSGetHostsResult"`
	} `xml:"CommandResponse"`
}

func (s *NamecheapSource) Fetch(ctx context.Context) ([]string, error) {
	seen := make(map[string]bool)
	var targets []string

	// Fetch all domains
	page := 1
	for {
		url := fmt.Sprintf(
			"https://api.namecheap.com/xml.response?ApiUser=%s&ApiKey=%s&UserName=%s&ClientIp=%s&Command=namecheap.domains.getList&PageSize=100&Page=%d",
			s.config.APIUser, s.config.APIKey, s.config.APIUser, s.config.ClientIP, page,
		)

		body, err := s.doRequest(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetch domains page %d: %w", page, err)
		}

		var resp ncDomainsResponse
		if err := xml.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parse domains: %w", err)
		}

		if len(resp.Errors.Error) > 0 {
			return nil, fmt.Errorf("namecheap API error: %s", resp.Errors.Error[0].Message)
		}

		for _, d := range resp.CommandResponse.DomainGetListResult.Domains {
			if d.Name != "" && !seen[d.Name] {
				seen[d.Name] = true
				targets = append(targets, d.Name)
			}

			// Fetch DNS hosts to discover subdomains
			subs, err := s.fetchHosts(ctx, d.Name)
			if err != nil {
				continue // Skip on error, don't fail entire import
			}
			for _, sub := range subs {
				if !seen[sub] {
					seen[sub] = true
					targets = append(targets, sub)
				}
			}
		}

		totalPages := 1
		if resp.CommandResponse.Paging.PageSize > 0 {
			totalPages = (resp.CommandResponse.Paging.TotalItems + resp.CommandResponse.Paging.PageSize - 1) / resp.CommandResponse.Paging.PageSize
		}
		if page >= totalPages {
			break
		}
		page++
	}

	return targets, nil
}

func (s *NamecheapSource) fetchHosts(ctx context.Context, domain string) ([]string, error) {
	// Split domain into SLD and TLD
	sld, tld := splitDomain(domain)
	if sld == "" {
		return nil, nil
	}

	url := fmt.Sprintf(
		"https://api.namecheap.com/xml.response?ApiUser=%s&ApiKey=%s&UserName=%s&ClientIp=%s&Command=namecheap.domains.dns.getHosts&SLD=%s&TLD=%s",
		s.config.APIUser, s.config.APIKey, s.config.APIUser, s.config.ClientIP, sld, tld,
	)

	body, err := s.doRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	var resp ncHostsResponse
	if err := xml.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	var subs []string
	for _, h := range resp.CommandResponse.DomainDNSGetHostsResult.Hosts {
		if h.Type == "A" || h.Type == "AAAA" || h.Type == "CNAME" {
			if h.Name != "@" && h.Name != "" {
				fqdn := h.Name + "." + domain
				subs = append(subs, fqdn)
			}
		}
	}
	return subs, nil
}

func (s *NamecheapSource) doRequest(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// splitDomain splits "example.com" into ("example", "com").
func splitDomain(domain string) (string, string) {
	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] == '.' {
			return domain[:i], domain[i+1:]
		}
	}
	return "", ""
}
