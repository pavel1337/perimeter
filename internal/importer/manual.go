package importer

import (
	"context"
	"strings"
)

type ManualSource struct {
	Input string
}

func (s *ManualSource) Name() string {
	return "manual"
}

func (s *ManualSource) Fetch(ctx context.Context) ([]string, error) {
	var targets []string
	lines := strings.SplitSeq(s.Input, "\n")
	for line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			targets = append(targets, trimmed)
		}
	}
	return targets, nil
}
