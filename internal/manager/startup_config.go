package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"go.yaml.in/yaml/v4"
)

type startupBindConfig struct {
	Address string `yaml:"address"`
	Port    *int   `yaml:"port"`
}

type startupDefaultsConfig struct {
	DefaultMaxAlertsPerRule int `yaml:"default_max_alerts_per_rule,omitempty"`
}

const (
	defaultBindAddress = "0.0.0.0"
	defaultBindPort    = 8080
)

// StartupConfig is the manager startup configuration loaded from manager.yaml.
type StartupConfig struct {
	Revision        string                `yaml:"-"`
	Bind            startupBindConfig     `yaml:"bind"`
	Defaults        startupDefaultsConfig `yaml:"defaults,omitempty"`
	Sinks           SinksConfig           `yaml:"sinks,omitempty"`
	Output          OutputConfig          `yaml:"output,omitempty"`
	DisableBaseline bool                  `yaml:"disable_baseline,omitempty"`
}

// SinksConfig maps an operator-defined sink name to its physical destination.
type SinksConfig map[string]SinkConfig

// SinkConfig describes one physical manager output destination.
type SinkConfig struct {
	Type      string `yaml:"type"`
	Bucket    string `yaml:"bucket,omitempty"`
	Region    string `yaml:"region,omitempty"`
	Prefix    string `yaml:"prefix,omitempty"`
	URI       string `yaml:"uri,omitempty"`
	ProjectID string `yaml:"project_id,omitempty"`
	Topic     string `yaml:"topic,omitempty"`
}

// OutputConfig maps a log name to one sink name.
type OutputConfig map[string]LogOutput

// LogOutput selects the named sink for one manager-ingested log.
type LogOutput struct {
	Destination string `yaml:"destination"`
}

// LoadStartupConfig reads and validates the manager startup config file.
func LoadStartupConfig(path string) (StartupConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return StartupConfig{}, fmt.Errorf("read startup config %s: %w", path, err)
	}

	var cfg StartupConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return StartupConfig{}, fmt.Errorf("parse startup config %s: %w", path, err)
	}
	if cfg.Bind.Address == "" {
		cfg.Bind.Address = defaultBindAddress
	}
	if cfg.Bind.Port == nil {
		port := defaultBindPort
		cfg.Bind.Port = &port
	}
	if *cfg.Bind.Port < 0 || *cfg.Bind.Port > 65535 {
		return StartupConfig{}, fmt.Errorf("bind.port must be between 0 and 65535")
	}
	if err := rule.ValidateMaxAlertsBound(
		cfg.Defaults.DefaultMaxAlertsPerRule,
		"defaults.default_max_alerts_per_rule",
	); err != nil {
		return StartupConfig{}, err
	}
	if err := validateSinks(cfg.Sinks); err != nil {
		return StartupConfig{}, err
	}
	if err := validateOutput(cfg.Output, cfg.Sinks); err != nil {
		return StartupConfig{}, err
	}
	sum := sha256.Sum256(data)
	cfg.Revision = "sha256:" + hex.EncodeToString(sum[:])
	return cfg, nil
}

// BindAddress returns the net/http listen address represented by bind config.
func (cfg StartupConfig) BindAddress() string {
	return net.JoinHostPort(cfg.Bind.Address, strconv.Itoa(*cfg.Bind.Port))
}

func validateSinks(sinks SinksConfig) error {
	for name, sc := range sinks {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("sinks: name must not be empty")
		}
		switch sc.Type {
		case "s3":
			if err := validateS3Sink(name, sc); err != nil {
				return err
			}
		case "gcs":
			if err := validateGCSSink(name, sc); err != nil {
				return err
			}
		case "pubsub":
			if err := validatePubSubSink(name, sc); err != nil {
				return err
			}
		default:
			return fmt.Errorf("sinks.%s.type %q is not one of s3/gcs/pubsub", name, sc.Type)
		}
	}
	return nil
}

func validateS3Sink(name string, sc SinkConfig) error {
	if sc.Bucket != "" && sc.URI != "" {
		return fmt.Errorf("sinks.%s: cannot set both bucket and uri", name)
	}
	if sc.Bucket == "" && sc.URI == "" {
		return fmt.Errorf("sinks.%s: bucket or uri is required", name)
	}
	if sc.URI != "" && !strings.HasPrefix(sc.URI, "s3://") {
		return fmt.Errorf("sinks.%s.uri must start with s3://", name)
	}
	if sc.Region == "" {
		return fmt.Errorf("sinks.%s.region is required for s3", name)
	}
	if sc.ProjectID != "" || sc.Topic != "" {
		return fmt.Errorf("sinks.%s: project_id and topic are only valid for pubsub", name)
	}
	return nil
}

func validateGCSSink(name string, sc SinkConfig) error {
	if sc.Bucket != "" && sc.URI != "" {
		return fmt.Errorf("sinks.%s: cannot set both bucket and uri", name)
	}
	if sc.Bucket == "" && sc.URI == "" {
		return fmt.Errorf("sinks.%s: bucket or uri is required", name)
	}
	if sc.URI != "" && !strings.HasPrefix(sc.URI, "gs://") {
		return fmt.Errorf("sinks.%s.uri must start with gs://", name)
	}
	if sc.Region != "" || sc.ProjectID != "" || sc.Topic != "" {
		return fmt.Errorf("sinks.%s: region, project_id, and topic are not valid for gcs", name)
	}
	return nil
}

func validatePubSubSink(name string, sc SinkConfig) error {
	if sc.ProjectID == "" {
		return fmt.Errorf("sinks.%s.project_id is required for pubsub", name)
	}
	if sc.Topic == "" {
		return fmt.Errorf("sinks.%s.topic is required for pubsub", name)
	}
	if sc.Bucket != "" || sc.Region != "" || sc.Prefix != "" || sc.URI != "" {
		return fmt.Errorf("sinks.%s: bucket, region, prefix, and uri are not valid for pubsub", name)
	}
	return nil
}

func validateOutput(output OutputConfig, sinks SinksConfig) error {
	for logName, logOutput := range output {
		if !knownOutputKind(logName) {
			return fmt.Errorf("output.%s: unknown log key", logName)
		}
		if strings.TrimSpace(logOutput.Destination) == "" {
			return fmt.Errorf("output.%s.destination: sink name is required", logName)
		}
		if _, ok := sinks[logOutput.Destination]; !ok {
			return fmt.Errorf("output.%s.destination %q is not a defined sink name", logName, logOutput.Destination)
		}
	}
	return nil
}

func knownOutputKind(logName string) bool {
	_, ok := sink.ParseLogKind(logName)
	return ok
}
