package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type HetznerRobotConfig struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type HetznerRobotSource struct {
	config HetznerRobotConfig
	client *http.Client
}

func NewHetznerRobotFactory() Factory {
	return func(config json.RawMessage) (Source, error) {
		var cfg HetznerRobotConfig
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, fmt.Errorf("invalid hetzner_robot config: %w", err)
		}
		if cfg.User == "" || cfg.Password == "" {
			return nil, fmt.Errorf("hetzner_robot: user and password are required")
		}
		return &HetznerRobotSource{
			config: cfg,
			client: &http.Client{Timeout: 15 * time.Second},
		}, nil
	}
}

func (s *HetznerRobotSource) Name() string {
	return "hetzner_robot"
}

type robotServerResponse []struct {
	Server struct {
		ServerIP string `json:"server_ip"`
	} `json:"server"`
}

func (s *HetznerRobotSource) Fetch(ctx context.Context) ([]string, error) {
	seen := make(map[string]bool)
	var targets []string

	// Fetch dedicated servers
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://robot-ws.your-server.de/server", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(s.config.User, s.config.Password)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch servers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("robot API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var servers robotServerResponse
	if err := json.Unmarshal(body, &servers); err != nil {
		return nil, fmt.Errorf("parse servers: %w", err)
	}

	for _, s := range servers {
		ip := s.Server.ServerIP
		if ip != "" && !seen[ip] {
			seen[ip] = true
			targets = append(targets, ip)
		}
	}

	return targets, nil
}
