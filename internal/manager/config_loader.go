package manager

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// ServedConfig is the config portion served by ConfigService.FetchConfig.
type ServedConfig struct {
	ConfigRevision          string
	DefaultMaxAlertsPerRule int
	OutputSettings          *managerv1.OutputSettings
}

type BaselineRuleSource interface {
	LoadForProvider(ctx context.Context, logger *slog.Logger, provider string) (rulesource.LoadedRules, error)
}

// RuleSourceCache loads optional local rules at FetchConfig time and reuses
// parsed rules while the file metadata is unchanged.
type RuleSourceCache struct {
	path string

	mu           sync.Mutex
	loaded       bool
	lastModified time.Time
	sizeBytes    int64
	rules        []rulesource.LoadedRules
}

func NewRuleSourceCache(path string) *RuleSourceCache {
	return &RuleSourceCache{path: path}
}

func (c *RuleSourceCache) Load(context.Context) ([]rulesource.LoadedRules, error) {
	if c == nil || c.path == "" {
		return nil, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	info, err := os.Stat(c.path)
	if err != nil {
		return nil, err
	}
	if c.loaded && info.ModTime().Equal(c.lastModified) && info.Size() == c.sizeBytes {
		return cloneLoadedRules(c.rules), nil
	}

	rules, err := LoadRuleSourcesFile(c.path)
	if err != nil {
		return nil, err
	}
	c.loaded = true
	c.lastModified = info.ModTime()
	c.sizeBytes = info.Size()
	c.rules = cloneLoadedRules(rules)
	return cloneLoadedRules(rules), nil
}

func LoadRuleSourcesFile(path string) ([]rulesource.LoadedRules, error) {
	rules, err := rulesource.LoadRulesFile(path)
	if err != nil {
		return nil, err
	}
	return []rulesource.LoadedRules{*rules}, nil
}

func cloneLoadedRules(in []rulesource.LoadedRules) []rulesource.LoadedRules {
	if len(in) == 0 {
		return nil
	}
	out := make([]rulesource.LoadedRules, len(in))
	copy(out, in)
	return out
}
