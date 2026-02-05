package importer

import "context"

// Source defines the interface for an import source.
type Source interface {
	Name() string
	Fetch(ctx context.Context) ([]string, error)
}
