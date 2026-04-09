package importer

import (
	"encoding/json"
	"fmt"
)

// Factory creates a Source from provider-specific JSON config.
type Factory func(config json.RawMessage) (Source, error)

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

func (r *Registry) Get(name string, config json.RawMessage) (Source, error) {
	f, ok := r.factories[name]
	if !ok {
		return nil, fmt.Errorf("unknown importer provider: %s", name)
	}
	return f(config)
}

func (r *Registry) List() []string {
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}
