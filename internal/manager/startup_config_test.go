package manager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadStartupConfig(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantAddress string
		wantPort    int
		wantBind    string
		wantDefault int
		wantErrText string
	}{
		{
			name: "valid startup config returns bind defaults",
			content: `
bind:
  address: 127.0.0.1
  port: 7443
default_max_alerts_per_rule: 25
`,
			wantAddress: "127.0.0.1",
			wantPort:    7443,
			wantBind:    "127.0.0.1:7443",
			wantDefault: 25,
		},
		{
			name: "missing bind address uses default",
			content: `
bind:
  address: ""
  port: 7443
`,
			wantAddress: "0.0.0.0",
			wantPort:    7443,
			wantBind:    "0.0.0.0:7443",
		},
		{
			name: "missing bind port uses default",
			content: `
bind:
  address: 127.0.0.1
`,
			wantAddress: "127.0.0.1",
			wantPort:    8080,
			wantBind:    "127.0.0.1:8080",
		},
		{
			name:        "missing bind uses defaults",
			content:     `{}`,
			wantAddress: "0.0.0.0",
			wantPort:    8080,
			wantBind:    "0.0.0.0:8080",
		},
		{
			name: "negative bind port returns error",
			content: `
bind:
  address: 127.0.0.1
  port: -1
`,
			wantErrText: "bind.port must be between 0 and 65535",
		},
		{
			name: "default above hard ceiling returns error",
			content: `
bind:
  address: 127.0.0.1
  port: 7443
default_max_alerts_per_rule: 101
`,
			wantErrText: "default_max_alerts_per_rule must be <= 100",
		},
		{
			name: "old defaults object is rejected",
			content: `
defaults:
  default_max_alerts_per_rule: 25
`,
			wantErrText: "field defaults not found",
		},
		{
			name: "unknown top-level field is rejected",
			content: `
unexpected_field: true
`,
			wantErrText: "field unexpected_field not found",
		},
		{
			name:        "invalid yaml returns error",
			content:     "bind: [",
			wantErrText: "parse startup config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadStartupConfigFromString(t, tt.content)
			if tt.wantErrText != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("error: got %q, want substring %q", err.Error(), tt.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("load startup config: %v", err)
			}
			if got.Bind.Address != tt.wantAddress {
				t.Fatalf("bind.address: got %q, want %q", got.Bind.Address, tt.wantAddress)
			}
			if got.Bind.Port == nil || *got.Bind.Port != tt.wantPort {
				t.Fatalf("bind.port: got %v, want %d", got.Bind.Port, tt.wantPort)
			}
			if got.BindAddress() != tt.wantBind {
				t.Fatalf("bind address: got %q, want %q", got.BindAddress(), tt.wantBind)
			}
			if got.DefaultMaxAlertsPerRule != tt.wantDefault {
				t.Fatalf("default_max_alerts_per_rule: got %d, want %d", got.DefaultMaxAlertsPerRule, tt.wantDefault)
			}
			if !strings.HasPrefix(got.Revision, "sha256:") {
				t.Fatalf("revision: got %q, want sha256 prefix", got.Revision)
			}
		})
	}
}

func TestLoadStartupConfig_SinksAndLogs(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantErr   string
		assertCfg func(*testing.T, StartupConfig)
	}{
		{
			name: "happy_sinks_and_logs",
			body: `
sinks:
  s3-prod:
    type: s3
    uri: s3://cicd-sensor-prod/logs/
    region: us-east-1
  pubsub-detect:
    type: pubsub
    project_id: cicd-sensor-prod
    topic: detections
logs:
  detection_log:
    sink: s3-prod
  summary_log:
    sink: s3-prod
`,
			assertCfg: func(t *testing.T, cfg StartupConfig) {
				t.Helper()
				if cfg.Sinks["s3-prod"].URI != "s3://cicd-sensor-prod/logs/" {
					t.Fatalf("s3 uri: got %q", cfg.Sinks["s3-prod"].URI)
				}
				got := cfg.Logs["detection_log"].Sink
				if got != "s3-prod" {
					t.Fatalf("detection sink: got %q", got)
				}
			},
		},
		{
			name: "sink_unknown_type",
			body: `
sinks:
  bad:
    type: stdout
`,
			wantErr: `sinks.bad.type "stdout" is not one of s3/gcs/pubsub`,
		},
		{
			name: "s3_sink_missing_uri",
			body: `
sinks:
  s3-prod:
    type: s3
    region: us-east-1
`,
			wantErr: "sinks.s3-prod.uri is required",
		},
		{
			name: "s3_sink_uri_wrong_scheme",
			body: `
sinks:
  s3-prod:
    type: s3
    uri: gs://bucket/logs
    region: us-east-1
`,
			wantErr: "sinks.s3-prod.uri must start with s3://",
		},
		{
			name: "s3_sink_missing_region",
			body: `
sinks:
  s3-prod:
    type: s3
    uri: s3://bucket/logs
`,
			wantErr: "sinks.s3-prod.region is required for s3",
		},
		{
			name: "s3_sink_with_pubsub_fields",
			body: `
sinks:
  s3-prod:
    type: s3
    uri: s3://bucket/logs
    region: us-east-1
    project_id: project
`,
			wantErr: "sinks.s3-prod: project_id and topic are only valid for pubsub",
		},
		{
			name: "gcs_sink_missing_uri",
			body: `
sinks:
  gcs-prod:
    type: gcs
`,
			wantErr: "sinks.gcs-prod.uri is required",
		},
		{
			name: "gcs_sink_uri_wrong_scheme",
			body: `
sinks:
  gcs-prod:
    type: gcs
    uri: s3://bucket/logs
`,
			wantErr: "sinks.gcs-prod.uri must start with gs://",
		},
		{
			name: "gcs_sink_with_pubsub_fields",
			body: `
sinks:
  gcs-prod:
    type: gcs
    uri: gs://bucket/logs
    project_id: project
`,
			wantErr: "sinks.gcs-prod: region, project_id, and topic are not valid for gcs",
		},
		{
			name: "pubsub_sink_missing_project_id",
			body: `
sinks:
  pubsub-detect:
    type: pubsub
    topic: detections
`,
			wantErr: "sinks.pubsub-detect.project_id is required for pubsub",
		},
		{
			name: "pubsub_sink_missing_topic",
			body: `
sinks:
  pubsub-detect:
    type: pubsub
    project_id: project
`,
			wantErr: "sinks.pubsub-detect.topic is required for pubsub",
		},
		{
			name: "pubsub_sink_with_object_storage_fields",
			body: `
sinks:
  pubsub-detect:
    type: pubsub
    project_id: project
    topic: detections
    uri: gs://bucket/logs
`,
			wantErr: "sinks.pubsub-detect: region and uri are not valid for pubsub",
		},
		{
			name: "sink_name_empty",
			body: `
sinks:
  "":
    type: gcs
    uri: gs://bucket/logs
`,
			wantErr: "sinks: name must not be empty",
		},
		{
			name: "logs_unknown_log_key",
			body: `
sinks:
  gcs-prod:
    type: gcs
    uri: gs://bucket/logs
logs:
  unknown:
    sink: gcs-prod
`,
			wantErr: "logs.unknown: unknown log key",
		},
		{
			name: "logs_sink_empty",
			body: `
sinks:
  gcs-prod:
    type: gcs
    uri: gs://bucket/logs
logs:
  detection_log:
    sink: ""
`,
			wantErr: "logs.detection_log.sink: sink name is required",
		},
		{
			name: "logs_sink_references_missing_sink",
			body: `
logs:
  detection_log:
    sink: missing
`,
			wantErr: `logs.detection_log.sink "missing" is not a defined sink name`,
		},
		{
			name: "old_output_key_is_rejected",
			body: `
sinks:
  gcs-prod:
    type: gcs
    uri: gs://bucket/logs
output:
  detection_log:
    destination: gcs-prod
`,
			wantErr: `field output not found`,
		},
		{
			name: "old_destination_key_is_rejected",
			body: `
sinks:
  gcs-prod:
    type: gcs
    uri: gs://bucket/logs
logs:
  detection_log:
    destination: gcs-prod
`,
			wantErr: `field destination not found`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadStartupConfigFromString(t, "bind:\n  address: 127.0.0.1\n  port: 7443\n"+tt.body)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error: got %q, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("load startup config: %v", err)
			}
			if tt.assertCfg != nil {
				tt.assertCfg(t, cfg)
			}
		})
	}
}

func loadStartupConfigFromString(t *testing.T, content string) (StartupConfig, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "manager.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	return LoadStartupConfig(path)
}
