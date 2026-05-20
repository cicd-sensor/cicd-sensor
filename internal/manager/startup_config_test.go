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
		wantDisable bool
		wantErr     bool
	}{
		{
			name: "valid startup config returns bind defaults",
			content: `
bind:
  address: 127.0.0.1
  port: 7443
defaults:
  default_max_alerts_per_rule: 25
disable_baseline: true
`,
			wantAddress: "127.0.0.1",
			wantPort:    7443,
			wantBind:    "127.0.0.1:7443",
			wantDefault: 25,
			wantDisable: true,
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
			wantErr: true,
		},
		{
			name: "default above hard ceiling returns error",
			content: `
bind:
  address: 127.0.0.1
  port: 7443
defaults:
  default_max_alerts_per_rule: 101
`,
			wantErr: true,
		},
		{
			name:    "invalid yaml returns error",
			content: "bind: [",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadStartupConfigFromString(t, tt.content)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
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
			if got.Defaults.DefaultMaxAlertsPerRule != tt.wantDefault {
				t.Fatalf("default_max_alerts_per_rule: got %d, want %d", got.Defaults.DefaultMaxAlertsPerRule, tt.wantDefault)
			}
			if got.DisableBaseline != tt.wantDisable {
				t.Fatalf("disable_baseline: got %v, want %v", got.DisableBaseline, tt.wantDisable)
			}
			if !strings.HasPrefix(got.Revision, "sha256:") {
				t.Fatalf("revision: got %q, want sha256 prefix", got.Revision)
			}
		})
	}
}

func TestLoadStartupConfig_SinksAndOutput(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantErr   string
		assertCfg func(*testing.T, StartupConfig)
	}{
		{
			name: "happy_sinks_and_outputs",
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
output:
  job_detection_log:
    destination: s3-prod
  job_result_log:
    destination: s3-prod
`,
			assertCfg: func(t *testing.T, cfg StartupConfig) {
				t.Helper()
				if cfg.Sinks["s3-prod"].URI != "s3://cicd-sensor-prod/logs/" {
					t.Fatalf("s3 uri: got %q", cfg.Sinks["s3-prod"].URI)
				}
				got := cfg.Output["job_detection_log"].Destination
				if got != "s3-prod" {
					t.Fatalf("detection destination: got %q", got)
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
			name: "output_unknown_log_key",
			body: `
sinks:
  gcs-prod:
    type: gcs
    uri: gs://bucket/logs
output:
  unknown:
    destination: gcs-prod
`,
			wantErr: "output.unknown: unknown log key",
		},
		{
			name: "output_destination_empty",
			body: `
sinks:
  gcs-prod:
    type: gcs
    uri: gs://bucket/logs
output:
  job_detection_log:
    destination: ""
`,
			wantErr: "output.job_detection_log.destination: sink name is required",
		},
		{
			name: "output_destination_references_missing_sink",
			body: `
output:
  job_detection_log:
    destination: missing
`,
			wantErr: `output.job_detection_log.destination "missing" is not a defined sink name`,
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
