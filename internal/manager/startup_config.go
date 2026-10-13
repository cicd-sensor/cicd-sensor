package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	oidcauth "github.com/cicd-sensor/cicd-sensor/internal/managerauth/oidc"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"go.yaml.in/yaml/v4"
)

type startupBindConfig struct {
	Address string `yaml:"address"`
	Port    *int   `yaml:"port"`
}

const (
	defaultBindAddress = "0.0.0.0"
	defaultBindPort    = 8080
)

// StartupConfig is the manager startup configuration loaded from manager.yaml.
type StartupConfig struct {
	Revision                string            `yaml:"-"`
	Bind                    startupBindConfig `yaml:"bind"`
	Auth                    AuthConfig        `yaml:"auth,omitempty"`
	DefaultMaxAlertsPerRule int               `yaml:"default_max_alerts_per_rule,omitempty"`
	DisableBaselineRules    bool              `yaml:"disable_baseline_rules,omitempty"`
	MonitorMode             bool              `yaml:"monitor_mode,omitempty"`
	RedactProcessArgs       *bool             `yaml:"redact_process_args,omitempty"`
	Sinks                   SinksConfig       `yaml:"sinks,omitempty"`
	Logs                    LogsConfig        `yaml:"logs,omitempty"`
}

// AuthConfig holds optional authentication settings beyond manager tokens.
type AuthConfig struct {
	OIDC OIDCAuthConfig `yaml:"oidc,omitempty"`
}

// OIDCAuthConfig is the GitHub Actions OIDC verification settings.
type OIDCAuthConfig struct {
	Enabled  bool                 `yaml:"enabled,omitempty"`
	Issuer   string               `yaml:"issuer,omitempty"`
	Audience string               `yaml:"audience,omitempty"`
	JWKSURL  string               `yaml:"jwks_url,omitempty"`
	Allow    []OIDCAllowlistEntry `yaml:"allow,omitempty"`
}

// OIDCAllowlistEntry is one exact-claim allowlist grant from manager.yaml.
// Pointer fields distinguish omitted keys (nil, no constraint) from
// explicit empty strings (rejected at load).
type OIDCAllowlistEntry struct {
	RepositoryOwner   *string `yaml:"repository_owner,omitempty"`
	Repository        *string `yaml:"repository,omitempty"`
	RepositoryOwnerID *string `yaml:"repository_owner_id,omitempty"`
	RepositoryID      *string `yaml:"repository_id,omitempty"`
}

// OIDCConfig converts YAML auth.oidc into the verifier config type.
// Explicit empty allowlist claim keys return an error (nil pointer =
// omitted / unconstrained).
func (cfg StartupConfig) OIDCConfig() (oidcauth.Config, error) {
	allow := make([]oidcauth.AllowEntry, 0, len(cfg.Auth.OIDC.Allow))
	for i, entry := range cfg.Auth.OIDC.Allow {
		decoded, err := oidcauth.AllowEntryFromOptional(
			entry.RepositoryOwner,
			entry.Repository,
			entry.RepositoryOwnerID,
			entry.RepositoryID,
		)
		if err != nil {
			return oidcauth.Config{}, fmt.Errorf("auth.oidc.allow[%d]: %w", i, err)
		}
		allow = append(allow, decoded)
	}
	return oidcauth.Config{
		Enabled:  cfg.Auth.OIDC.Enabled,
		Issuer:   cfg.Auth.OIDC.Issuer,
		Audience: cfg.Auth.OIDC.Audience,
		JWKSURL:  cfg.Auth.OIDC.JWKSURL,
		Allow:    allow,
	}, nil
}

// SinksConfig maps an operator-defined sink name to its physical destination.
type SinksConfig map[string]SinkConfig

// SinkConfig describes one physical manager output destination.
type SinkConfig struct {
	Type         string `yaml:"type"`
	URI          string `yaml:"uri,omitempty"`
	Region       string `yaml:"region,omitempty"`
	UsePathStyle bool   `yaml:"use_path_style,omitempty"`
	ProjectID    string `yaml:"project_id,omitempty"`
	Topic        string `yaml:"topic,omitempty"`
}

// LogsConfig maps a log type to one sink name.
type LogsConfig map[string]LogOutput

// LogOutput selects the named sink for one manager-ingested log.
type LogOutput struct {
	Sink string `yaml:"sink"`
}

// LoadStartupConfig reads and validates the manager startup config file.
func LoadStartupConfig(path string) (StartupConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return StartupConfig{}, fmt.Errorf("read startup config %s: %w", path, err)
	}

	var cfg StartupConfig
	if err := yaml.Load(data, &cfg, yaml.WithKnownFields()); err != nil {
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
		cfg.DefaultMaxAlertsPerRule,
		"default_max_alerts_per_rule",
	); err != nil {
		return StartupConfig{}, err
	}
	if err := validateSinks(cfg.Sinks); err != nil {
		return StartupConfig{}, err
	}
	if err := validateLogs(cfg.Logs, cfg.Sinks); err != nil {
		return StartupConfig{}, err
	}
	oidcCfg, err := cfg.OIDCConfig()
	if err != nil {
		return StartupConfig{}, err
	}
	if err := oidcCfg.Validate(); err != nil {
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

// ProcessArgsRedactionEnabled keeps redaction enabled when the setting is
// absent, including configs written before the setting existed.
func (cfg StartupConfig) ProcessArgsRedactionEnabled() bool {
	return cfg.RedactProcessArgs == nil || *cfg.RedactProcessArgs
}

func validateSinks(sinks SinksConfig) error {
	for name, sc := range sinks {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("sinks: name must not be empty")
		}
		switch sc.Type {
		case "aws_s3":
			if err := validateS3Sink(name, sc); err != nil {
				return err
			}
		case "google_storage":
			if err := validateGCSSink(name, sc); err != nil {
				return err
			}
		case "google_pubsub":
			if err := validatePubSubSink(name, sc); err != nil {
				return err
			}
		case "azure_blob":
			if err := validateAzureBlobSink(name, sc); err != nil {
				return err
			}
		default:
			return fmt.Errorf("sinks.%s.type %q is not one of aws_s3/google_storage/google_pubsub/azure_blob", name, sc.Type)
		}
	}
	return nil
}

func validateS3Sink(name string, sc SinkConfig) error {
	if sc.URI == "" {
		return fmt.Errorf("sinks.%s.uri is required", name)
	}
	if !strings.HasPrefix(sc.URI, "s3://") {
		return fmt.Errorf("sinks.%s.uri must start with s3://", name)
	}
	if sc.Region == "" {
		return fmt.Errorf("sinks.%s.region is required for aws_s3", name)
	}
	if sc.ProjectID != "" || sc.Topic != "" {
		return fmt.Errorf("sinks.%s: project_id and topic are only valid for google_pubsub", name)
	}
	return nil
}

func validateGCSSink(name string, sc SinkConfig) error {
	if sc.URI == "" {
		return fmt.Errorf("sinks.%s.uri is required", name)
	}
	if !strings.HasPrefix(sc.URI, "gs://") {
		return fmt.Errorf("sinks.%s.uri must start with gs://", name)
	}
	if sc.Region != "" || sc.ProjectID != "" || sc.Topic != "" {
		return fmt.Errorf("sinks.%s: region, project_id, and topic are not valid for google_storage", name)
	}
	if sc.UsePathStyle {
		return fmt.Errorf("sinks.%s: use_path_style is only valid for aws_s3", name)
	}
	return nil
}

func validatePubSubSink(name string, sc SinkConfig) error {
	if sc.ProjectID == "" {
		return fmt.Errorf("sinks.%s.project_id is required for google_pubsub", name)
	}
	if sc.Topic == "" {
		return fmt.Errorf("sinks.%s.topic is required for google_pubsub", name)
	}
	if sc.Region != "" || sc.URI != "" {
		return fmt.Errorf("sinks.%s: region and uri are not valid for google_pubsub", name)
	}
	if sc.UsePathStyle {
		return fmt.Errorf("sinks.%s: use_path_style is only valid for aws_s3", name)
	}
	return nil
}

func validateAzureBlobSink(name string, sc SinkConfig) error {
	if sc.URI == "" {
		return fmt.Errorf("sinks.%s.uri is required", name)
	}
	if !strings.HasPrefix(sc.URI, "https://") {
		return fmt.Errorf("sinks.%s.uri must start with https://", name)
	}
	if sc.Region != "" || sc.ProjectID != "" || sc.Topic != "" {
		return fmt.Errorf("sinks.%s: region, project_id, and topic are not valid for azure_blob", name)
	}
	if sc.UsePathStyle {
		return fmt.Errorf("sinks.%s: use_path_style is only valid for aws_s3", name)
	}
	return nil
}

func validateLogs(logs LogsConfig, sinks SinksConfig) error {
	for logName, logOutput := range logs {
		if !knownOutputKind(logName) {
			return fmt.Errorf("logs.%s: unknown log key", logName)
		}
		if strings.TrimSpace(logOutput.Sink) == "" {
			return fmt.Errorf("logs.%s.sink: sink name is required", logName)
		}
		if _, ok := sinks[logOutput.Sink]; !ok {
			return fmt.Errorf("logs.%s.sink %q is not a defined sink name", logName, logOutput.Sink)
		}
	}
	return nil
}

func knownOutputKind(logName string) bool {
	_, ok := logtype.Parse(logName)
	return ok
}
