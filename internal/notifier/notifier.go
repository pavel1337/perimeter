package notifier

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"time"

	"perimeter/ent"
	"perimeter/ent/notifierconfig"
)

// Event represents a security event that triggers notifications.
type Event struct {
	Type      EventType
	Target    string
	Message   string
	Details   map[string]any
	Timestamp time.Time
}

type EventType string

const (
	EventNewOpenPorts EventType = "new_open_ports"
	EventSSLGradeDrop EventType = "ssl_grade_drop"
	EventCertExpiring EventType = "cert_expiring"
	EventCSPIssues    EventType = "csp_issues"
)

// AllEventTypes returns every event type in declaration order.
func AllEventTypes() []EventType {
	return []EventType{EventNewOpenPorts, EventSSLGradeDrop, EventCertExpiring, EventCSPIssues}
}

// Notifier sends alerts for security events.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, event Event) error
}

// Factory creates a Notifier from provider-specific JSON config.
type Factory func(config json.RawMessage) (Notifier, error)

// Registry maps provider names to their factory functions.
type Registry struct {
	factories map[string]Factory
}

func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]Factory),
	}
}

func (r *Registry) Register(name string, f Factory) {
	r.factories[name] = f
}

func (r *Registry) Get(name string, config json.RawMessage) (Notifier, error) {
	f, ok := r.factories[name]
	if !ok {
		return nil, fmt.Errorf("unknown notifier provider: %s", name)
	}
	return f(config)
}

func (r *Registry) List() []string {
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Dispatcher loads enabled notifier configs and fans out events.
type Dispatcher struct {
	client   *ent.Client
	registry *Registry
}

func NewDispatcher(client *ent.Client, registry *Registry) *Dispatcher {
	return &Dispatcher{client: client, registry: registry}
}

func (d *Dispatcher) Dispatch(ctx context.Context, event Event) {
	configs, err := d.client.NotifierConfig.Query().
		Where(notifierconfig.EnabledEQ(true)).
		All(ctx)
	if err != nil {
		log.Printf("Notifier dispatch: error loading configs: %v", err)
		return
	}

	for _, cfg := range configs {
		// Empty events means every event type.
		if len(cfg.Events) > 0 && !slices.Contains(cfg.Events, string(event.Type)) {
			continue
		}
		n, err := d.registry.Get(cfg.Provider.String(), json.RawMessage(cfg.Config))
		if err != nil {
			log.Printf("Notifier dispatch: failed to create %s (id=%d): %v", cfg.Provider, cfg.ID, err)
			continue
		}
		if err := n.Notify(ctx, event); err != nil {
			log.Printf("Notifier dispatch: %s (id=%d) failed: %v", cfg.Provider, cfg.ID, err)
		}
	}
}
