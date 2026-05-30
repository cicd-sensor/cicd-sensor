// Package projectconfig loads the project-side config passed to
// `cicd-sensor project start --config-file`.
//
// Keep this package narrow: fields here are explicit project-owned inputs, not
// a catch-all for agent runtime defaults.
package projectconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v4"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

// ProjectConfig contains project-owned inputs accepted by project start.
type ProjectConfig struct {
	DefaultMaxAlertsPerRule *int `yaml:"default_max_alerts_per_rule,omitempty"`
	DisableBaselineRules    bool `yaml:"disable_baseline_rules,omitempty"`
	MonitorMode             bool `yaml:"monitor_mode,omitempty"`
}

// Load reads a project config file and rejects unknown fields.
func Load(path string) (ProjectConfig, error) {
	data, err := readConfigFile(path)
	if err != nil {
		return ProjectConfig{}, fmt.Errorf("read project config %s: %w", path, err)
	}

	var cfg ProjectConfig
	if err := yaml.Load(data, &cfg, yaml.WithKnownFields()); err != nil {
		return ProjectConfig{}, fmt.Errorf("parse project config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return ProjectConfig{}, err
	}
	return cfg, nil
}

func readConfigFile(path string) ([]byte, error) {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(name)
}

// Validate accepts omitted defaults and checks the value only when configured.
func (c ProjectConfig) Validate() error {
	if c.DefaultMaxAlertsPerRule == nil {
		return nil
	}
	return rule.ValidateMaxAlertsBound(*c.DefaultMaxAlertsPerRule, "default_max_alerts_per_rule")
}
