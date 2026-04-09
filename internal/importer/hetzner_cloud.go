package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type HetznerCloudConfig struct {
	APIToken string `json:"api_token"`
}

type HetznerCloudSource struct {
	config HetznerCloudConfig
	client *http.Client
}

func NewHetznerCloudFactory() Factory {
	return func(config json.RawMessage) (Source, error) {
		var cfg HetznerCloudConfig
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, fmt.Errorf("invalid hetzner_cloud config: %w", err)
		}
		if cfg.APIToken == "" {
			return nil, fmt.Errorf("hetzner_cloud: api_token is required")
		}
		return &HetznerCloudSource{
			config: cfg,
			client: &http.Client{Timeout: 15 * time.Second},
		}, nil
	}
}

func (s *HetznerCloudSource) Name() string {
	return "hetzner_cloud"
}

type hcloudServersResponse struct {
	Servers []hcloudServer `json:"servers"`
	Meta    struct {
		Pagination struct {
			NextPage *int `json:"next_page"`
		} `json:"pagination"`
	} `json:"meta"`
}

type hcloudServer struct {
	PublicNet struct {
		IPv4 struct {
			IP string `json:"ip"`
		} `json:"ipv4"`
		IPv6 struct {
			IP string `json:"ip"`
		} `json:"ipv6"`
	} `json:"public_net"`
}

type hcloudFloatingIPsResponse struct {
	FloatingIPs []struct {
		IP string `json:"ip"`
	} `json:"floating_ips"`
	Meta struct {
		Pagination struct {
			NextPage *int `json:"next_page"`
		} `json:"pagination"`
	} `json:"meta"`
}

func (s *HetznerCloudSource) Fetch(ctx context.Context) ([]string, error) {
	seen := make(map[string]bool)
	var targets []string

	// Fetch server IPs
	page := 1
	for {
		url := fmt.Sprintf("https://api.hetzner.cloud/v1/servers?page=%d&per_page=50", page)
		body, err := s.doRequest(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetch servers: %w", err)
		}

		var resp hcloudServersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parse servers: %w", err)
		}

		for _, srv := range resp.Servers {
			if ip := srv.PublicNet.IPv4.IP; ip != "" && !seen[ip] {
				seen[ip] = true
				targets = append(targets, ip)
			}
		}

		if resp.Meta.Pagination.NextPage == nil {
			break
		}
		page = *resp.Meta.Pagination.NextPage
	}

	// Fetch floating IPs
	page = 1
	for {
		url := fmt.Sprintf("https://api.hetzner.cloud/v1/floating_ips?page=%d&per_page=50", page)
		body, err := s.doRequest(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetch floating_ips: %w", err)
		}

		var resp hcloudFloatingIPsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parse floating_ips: %w", err)
		}

		for _, fip := range resp.FloatingIPs {
			if fip.IP != "" && !seen[fip.IP] {
				seen[fip.IP] = true
				targets = append(targets, fip.IP)
			}
		}

		if resp.Meta.Pagination.NextPage == nil {
			break
		}
		page = *resp.Meta.Pagination.NextPage
	}

	return targets, nil
}

func (s *HetznerCloudSource) doRequest(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.config.APIToken)

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
