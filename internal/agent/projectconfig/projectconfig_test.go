package projectconfig

import (
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		content     string
		want        *int
		wantDisable bool
		wantErrText string
	}{
		{
			name:    "empty config is valid",
			content: "{}\n",
		},
		{
			name: "default max alerts is loaded",
			content: `
default_max_alerts_per_rule: 7
`,
			want: intPtr(7),
		},
		{
			name: "disable baseline rules is loaded",
			content: `
disable_baseline_rules: true
`,
			wantDisable: true,
		},
		{
			name: "negative default is rejected",
			content: `
default_max_alerts_per_rule: -1
`,
			wantErrText: "must be non-negative",
		},
		{
			name: "hard ceiling is enforced",
			content: `
default_max_alerts_per_rule: 101
`,
			wantErrText: "must be <= " + "100",
		},
		{
			name:        "invalid yaml is rejected",
			content:     "default_max_alerts_per_rule: [\n",
			wantErrText: "parse project config",
		},
		{
			name: "manager url is not a project config field",
			content: `
manager:
  url: https://project-manager.example.com
`,
			wantErrText: "field manager not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			path := filepath.Join(dir, "project.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("write config: %v", err)
			}

			got, err := Load(path)
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
				t.Fatalf("Load: %v", err)
			}
			switch {
			case got.DefaultMaxAlertsPerRule == nil && tt.want == nil:
			case got.DefaultMaxAlertsPerRule == nil || tt.want == nil:
				t.Fatalf("default max alerts: got %v, want %v", got.DefaultMaxAlertsPerRule, tt.want)
			case *got.DefaultMaxAlertsPerRule != *tt.want:
				t.Fatalf("default max alerts: got %d, want %d", *got.DefaultMaxAlertsPerRule, *tt.want)
			}
			if got.DisableBaselineRules != tt.wantDisable {
				t.Fatalf("disable baseline rules: got %v, want %v", got.DisableBaselineRules, tt.wantDisable)
			}
		})
	}
}

func TestProjectConfigValidate_HardCeilingTracksSharedConstant(t *testing.T) {
	t.Parallel()

	cfg := ProjectConfig{DefaultMaxAlertsPerRule: intPtr(rule.MaxAlertsHardCeiling + 1)}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected ceiling error")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing.yaml")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "read project config") {
		t.Fatalf("error: got %q, want read project config context", err.Error())
	}
}

func intPtr(v int) *int {
	return &v
}
