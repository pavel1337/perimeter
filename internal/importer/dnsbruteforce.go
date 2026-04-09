package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Default subdomain wordlist — common subdomains to check.
var defaultWordlist = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
	"dns", "dns1", "dns2", "mx", "mx1", "mx2", "imap", "blog", "dev", "staging",
	"api", "app", "admin", "portal", "vpn", "remote", "test", "shop", "store",
	"cdn", "media", "static", "assets", "img", "images", "video", "docs",
	"wiki", "help", "support", "status", "monitor", "grafana", "kibana",
	"jenkins", "ci", "cd", "git", "gitlab", "github", "bitbucket",
	"jira", "confluence", "slack", "chat", "meet", "calendar",
	"db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
	"search", "solr", "rabbitmq", "kafka", "mq",
	"auth", "sso", "login", "oauth", "id", "identity",
	"proxy", "gateway", "lb", "load-balancer", "haproxy", "nginx",
	"web", "web1", "web2", "srv", "server", "node", "worker",
	"backup", "bak", "old", "new", "beta", "alpha", "demo", "sandbox",
	"internal", "intranet", "extranet", "corp", "office",
	"m", "mobile", "wap",
	"cpanel", "whm", "plesk", "panel",
	"autodiscover", "autoconfig",
	"s3", "storage", "cloud", "aws", "gcp", "azure",
}

type DNSBruteforceConfig struct {
	Domain   string   `json:"domain"`
	Wordlist []string `json:"wordlist,omitempty"`
}

type DNSBruteforceSource struct {
	config DNSBruteforceConfig
}

func NewDNSBruteforceFactory() Factory {
	return func(config json.RawMessage) (Source, error) {
		var cfg DNSBruteforceConfig
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, fmt.Errorf("invalid dns_bruteforce config: %w", err)
		}
		if cfg.Domain == "" {
			return nil, fmt.Errorf("dns_bruteforce: domain is required")
		}
		if len(cfg.Wordlist) == 0 {
			cfg.Wordlist = defaultWordlist
		}
		return &DNSBruteforceSource{config: cfg}, nil
	}
}

func (s *DNSBruteforceSource) Name() string {
	return "dns_bruteforce"
}

func (s *DNSBruteforceSource) Fetch(ctx context.Context) ([]string, error) {
	var found []string
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, network, address)
		},
	}

	for _, sub := range s.config.Wordlist {
		select {
		case <-ctx.Done():
			return found, ctx.Err()
		default:
		}

		fqdn := sub + "." + s.config.Domain
		ips, err := resolver.LookupIPAddr(ctx, fqdn)
		if err != nil {
			continue // Doesn't resolve — skip
		}
		if len(ips) > 0 {
			found = append(found, fqdn)
		}
	}

	return found, nil
}
