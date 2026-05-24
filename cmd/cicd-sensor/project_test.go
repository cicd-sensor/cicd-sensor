package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestBuildProjectStartRequest(t *testing.T) {
	tests := []struct {
		name        string
		identity    jobIdentityFlags
		want        map[string]any
		wantErrText string
	}{
		{
			name:     "github collects all required fields",
			identity: githubIdentity(),
			want: map[string]any{
				"provider":                  "github",
				"provider_host":             "github.com",
				"project_path":              "acme/example",
				"github_run_id":             "123",
				"github_job":                "build",
				"github_run_attempt":        "2",
				"github_runner_tracking_id": "runner-1",
			},
		},
		{
			name:        "missing platform is rejected",
			identity:    jobIdentityFlags{},
			wantErrText: "provider is required",
		},
		{
			name: "unsupported provider is rejected",
			identity: jobIdentityFlags{
				Provider:     "circle",
				ProviderHost: "ci.example.com",
				ProjectPath:  "acme/example",
			},
			wantErrText: "provider must be github or gitlab",
		},
		{
			name: "missing github runner tracking id is rejected",
			identity: jobIdentityFlags{
				Provider:         "github",
				ProviderHost:     "github.com",
				ProjectPath:      "acme/example",
				GitHubRunID:      "123",
				GitHubJob:        "build",
				GitHubRunAttempt: "1",
			},
			wantErrText: "github-runner-tracking-id is required",
		},
		{
			name: "missing gitlab job id is rejected",
			identity: jobIdentityFlags{
				Provider:     "gitlab",
				ProviderHost: "gitlab.example.com",
				ProjectPath:  "group/project",
			},
			wantErrText: "gitlab-job-id is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildProjectStartRequest(tc.identity, jobMetadataFlags{}, "", "", managerConnectionConfig{}, false)
			if tc.wantErrText != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tc.wantErrText) {
					t.Fatalf("error: got %q, want substring %q", err.Error(), tc.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildProjectStartRequest: %v", err)
			}

			for key, want := range tc.want {
				if got[key] != want {
					t.Fatalf("%s: got %q, want %q", key, got[key], want)
				}
			}
		})
	}
}

func TestBuildProjectStartRequest_LoadsProjectConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "project.yaml")
	if err := os.WriteFile(configPath, []byte("default_max_alerts_per_rule: 7\n"), 0o644); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	got, err := buildProjectStartRequest(githubIdentity(), jobMetadataFlags{}, configPath, "", managerConnectionConfig{}, false)
	if err != nil {
		t.Fatalf("buildProjectStartRequest: %v", err)
	}
	if got["default_max_alerts_per_rule"] != 7 {
		t.Fatalf("default_max_alerts_per_rule: got %#v, want 7", got["default_max_alerts_per_rule"])
	}
}

func TestBuildProjectStartRequest_EmptyProjectConfigOmitsDefaultMaxAlerts(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "project.yaml")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	got, err := buildProjectStartRequest(githubIdentity(), jobMetadataFlags{}, configPath, "", managerConnectionConfig{}, false)
	if err != nil {
		t.Fatalf("buildProjectStartRequest: %v", err)
	}
	if _, ok := got["default_max_alerts_per_rule"]; ok {
		t.Fatalf("default_max_alerts_per_rule: got unexpected field %#v", got["default_max_alerts_per_rule"])
	}
}

func TestBuildProjectStartRequest_ZeroDefaultMaxAlertsIsUnset(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "project.yaml")
	if err := os.WriteFile(configPath, []byte("default_max_alerts_per_rule: 0\n"), 0o644); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	got, err := buildProjectStartRequest(githubIdentity(), jobMetadataFlags{}, configPath, "", managerConnectionConfig{}, false)
	if err != nil {
		t.Fatalf("buildProjectStartRequest: %v", err)
	}
	if _, ok := got["default_max_alerts_per_rule"]; ok {
		t.Fatalf("default_max_alerts_per_rule: got unexpected field %#v", got["default_max_alerts_per_rule"])
	}
}

func TestBuildProjectStartRequest_IncludesNestedMetadata(t *testing.T) {
	got, err := buildProjectStartRequest(githubIdentity(), jobMetadataFlags{
		CommitSHA:         "abc123",
		RefName:           "main",
		Trigger:           "push",
		ActorID:           "1001",
		ActorName:         "alice",
		GitHubWorkflowRef: "acme/example/.github/workflows/build.yml@refs/heads/main",
		GitHubWorkflowSHA: "def456",
		GitHubWorkflow:    "build",
	}, "", "", managerConnectionConfig{}, false)
	if err != nil {
		t.Fatalf("buildProjectStartRequest: %v", err)
	}
	metadata, ok := got["metadata"].(map[string]string)
	if !ok {
		t.Fatalf("metadata: got %#v", got["metadata"])
	}
	want := map[string]string{
		"commit_sha":          "abc123",
		"ref_name":            "main",
		"trigger":             "push",
		"actor_id":            "1001",
		"actor_name":          "alice",
		"github_workflow_ref": "acme/example/.github/workflows/build.yml@refs/heads/main",
		"github_workflow_sha": "def456",
		"github_workflow":     "build",
	}
	for key, wantValue := range want {
		if metadata[key] != wantValue {
			t.Fatalf("metadata[%s]: got %q, want %q", key, metadata[key], wantValue)
		}
	}
}

func TestBuildProjectStartRequest_LoadsProjectRules(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "project-config.yaml")
	if err := os.WriteFile(configPath, []byte("default_max_alerts_per_rule: 7\n"), 0o644); err != nil {
		t.Fatalf("write project config: %v", err)
	}
	rulesPath := writeProjectRuleFile(t, t.TempDir())

	got, err := buildProjectStartRequest(githubIdentity(), jobMetadataFlags{}, configPath, rulesPath, managerConnectionConfig{}, false)
	if err != nil {
		t.Fatalf("buildProjectStartRequest: %v", err)
	}
	sources, ok := got["rule_sources"].([]rulesource.LoadedRules)
	if !ok {
		t.Fatalf("rule_sources type: got %#v", got["rule_sources"])
	}
	if len(sources) != 1 {
		t.Fatalf("rule_sources: got %d, want 1", len(sources))
	}
	sets := sources[0].RuleSets
	if len(sets) != 1 {
		t.Fatalf("rule_sets: got %d, want 1", len(sets))
	}
	if sets[0].RulesetID != "project" {
		t.Fatalf("ruleset_id: got %q, want project", sets[0].RulesetID)
	}
}

func TestBuildProjectStartRequest_RulesWithoutConfig(t *testing.T) {
	rulesPath := writeProjectRuleFile(t, t.TempDir())

	got, err := buildProjectStartRequest(githubIdentity(), jobMetadataFlags{}, "", rulesPath, managerConnectionConfig{}, false)
	if err != nil {
		t.Fatalf("buildProjectStartRequest: %v", err)
	}
	sources, ok := got["rule_sources"].([]rulesource.LoadedRules)
	if !ok {
		t.Fatalf("rule_sources type: got %#v", got["rule_sources"])
	}
	if len(sources) != 1 {
		t.Fatalf("rule_sources: got %d, want 1", len(sources))
	}
	sets := sources[0].RuleSets
	if len(sets) != 1 {
		t.Fatalf("rule_sets: got %d, want 1", len(sets))
	}
	if _, ok := got["default_max_alerts_per_rule"]; ok {
		t.Fatalf("default_max_alerts_per_rule: got unexpected field %#v", got["default_max_alerts_per_rule"])
	}
}

func TestBuildProjectStartRequest_ConfigWithoutRules(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "project.yaml")
	if err := os.WriteFile(configPath, []byte("default_max_alerts_per_rule: 6\n"), 0o644); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	got, err := buildProjectStartRequest(githubIdentity(), jobMetadataFlags{}, configPath, "", managerConnectionConfig{}, false)
	if err != nil {
		t.Fatalf("buildProjectStartRequest: %v", err)
	}
	if got["default_max_alerts_per_rule"] != 6 {
		t.Fatalf("default_max_alerts_per_rule: got %#v, want 6", got["default_max_alerts_per_rule"])
	}
	if _, ok := got["rule_sources"]; ok {
		t.Fatalf("rule_sources: got unexpected field %#v", got["rule_sources"])
	}
}

func TestBuildProjectStartRequest_LoadsProjectManager(t *testing.T) {
	token := managerauth.TokenPrefix + strings.Repeat("a", 64)

	got, err := buildProjectStartRequest(githubIdentity(), jobMetadataFlags{}, "", "", managerConnectionConfig{
		URL:   "https://project-manager.example.com",
		Token: token,
	}, false)
	if err != nil {
		t.Fatalf("buildProjectStartRequest: %v", err)
	}
	if got["manager_url"] != "https://project-manager.example.com" {
		t.Fatalf("manager_url: got %#v", got["manager_url"])
	}
	if got["manager_token"] != token {
		t.Fatalf("manager_token: got %#v, want token", got["manager_token"])
	}
}

func TestBuildProjectStartRequest_IncludesDebugEnabled(t *testing.T) {
	got, err := buildProjectStartRequest(githubIdentity(), jobMetadataFlags{}, "", "", managerConnectionConfig{}, true)
	if err != nil {
		t.Fatalf("buildProjectStartRequest: %v", err)
	}
	if got["debug_enabled"] != true {
		t.Fatalf("debug_enabled: got %#v, want true", got["debug_enabled"])
	}
}

func TestBuildProjectStartRequest_OmitsDebugEnabledWhenFalse(t *testing.T) {
	got, err := buildProjectStartRequest(githubIdentity(), jobMetadataFlags{}, "", "", managerConnectionConfig{}, false)
	if err != nil {
		t.Fatalf("buildProjectStartRequest: %v", err)
	}
	if _, ok := got["debug_enabled"]; ok {
		t.Fatalf("debug_enabled: got unexpected field %#v", got["debug_enabled"])
	}
}

func TestBuildProjectStartRequest_ProjectManagerRequiresToken(t *testing.T) {
	_, err := buildProjectStartRequest(githubIdentity(), jobMetadataFlags{}, "", "", managerConnectionConfig{URL: "https://project-manager.example.com"}, false)
	if err == nil || !strings.Contains(err.Error(), "requires CICD_SENSOR_MANAGER_TOKEN") {
		t.Fatalf("error: got %v, want token requirement", err)
	}
}

func TestBuildProjectStartRequest_ProjectManagerRejectsLocalRules(t *testing.T) {
	rulesPath := filepath.Join(t.TempDir(), "rules.yaml")

	_, err := buildProjectStartRequest(githubIdentity(), jobMetadataFlags{}, "", rulesPath, managerConnectionConfig{
		URL:   "https://project-manager.example.com",
		Token: managerauth.TokenPrefix + strings.Repeat("a", 64),
	}, false)
	if err == nil || !strings.Contains(err.Error(), "cannot be combined with --rules-file") {
		t.Fatalf("error: got %v, want rules conflict", err)
	}
}

func TestBuildProjectStartRequest_ProjectManagerRejectsAndDoesNotReadConfig(t *testing.T) {
	missingConfig := filepath.Join(t.TempDir(), "missing-project.yaml")

	_, err := buildProjectStartRequest(githubIdentity(), jobMetadataFlags{}, missingConfig, "", managerConnectionConfig{
		URL:   "https://project-manager.example.com",
		Token: managerauth.TokenPrefix + strings.Repeat("a", 64),
	}, false)
	if err == nil || !strings.Contains(err.Error(), "cannot be combined with --config-file") {
		t.Fatalf("error: got %v, want config conflict without reading config", err)
	}
}

func TestWriteProjectResult(t *testing.T) {
	body := []byte(`{"status":"ok"}`)

	t.Run("stdout", func(t *testing.T) {
		var out strings.Builder
		if err := writeProjectResult("", body, &out); err != nil {
			t.Fatalf("writeProjectResult: %v", err)
		}
		if out.String() != string(body) {
			t.Fatalf("stdout: got %q, want %q", out.String(), string(body))
		}
	})

	t.Run("file", func(t *testing.T) {
		outputFile := filepath.Join(t.TempDir(), "summary.json")
		if err := writeProjectResult(outputFile, body, io.Discard); err != nil {
			t.Fatalf("writeProjectResult: %v", err)
		}
		got, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatalf("read output: %v", err)
		}
		if string(got) != string(body) {
			t.Fatalf("file body: got %q, want %q", got, string(body))
		}
	})

	t.Run("writer error", func(t *testing.T) {
		err := writeProjectResult("", body, errWriter{})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "write stdout") {
			t.Fatalf("error: got %q", err.Error())
		}
	})

	t.Run("file error", func(t *testing.T) {
		err := writeProjectResult(filepath.Join(t.TempDir(), "missing", "summary.json"), body, io.Discard)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "write ") {
			t.Fatalf("error: got %q", err.Error())
		}
	})
}

func TestBuildJobIdentityRequest_OmitsResultPathFields(t *testing.T) {
	got, err := buildJobIdentityRequest(githubIdentity())
	if err != nil {
		t.Fatalf("buildJobIdentityRequest: %v", err)
	}
	if got["provider"] != "github" {
		t.Fatalf("provider: got %q, want github", got["provider"])
	}
	for _, key := range []string{"github_workspace", "gitlab_project_dir", "artifact_path"} {
		if _, ok := got[key]; ok {
			t.Fatalf("%s: got unexpected field %#v", key, got[key])
		}
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestBuildJobIdentityRequest_ValidatesIdentityFields(t *testing.T) {
	_, err := buildJobIdentityRequest(jobIdentityFlags{
		Provider:     "github",
		ProviderHost: "github.com",
		ProjectPath:  "acme/example",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "github-run-id is required") {
		t.Fatalf("error: got %q", err.Error())
	}
}

func githubIdentity() jobIdentityFlags {
	return jobIdentityFlags{
		Provider:               "github",
		ProviderHost:           "github.com",
		ProjectPath:            "acme/example",
		GitHubRunID:            "123",
		GitHubJob:              "build",
		GitHubRunAttempt:       "2",
		GitHubRunnerTrackingID: "runner-1",
	}
}

func gitlabIdentity() jobIdentityFlags {
	return jobIdentityFlags{
		Provider:     "gitlab",
		ProviderHost: "gitlab.example.com",
		ProjectPath:  "group/project",
		GitLabJobID:  "789",
	}
}

func writeProjectRuleFile(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, "project.yaml")
	if err := os.WriteFile(path, []byte(`
rule_sets:
  - ruleset_id: "project"
    rules:
      - rule_id: "project_exec"
        event_type: "process_exec"
        condition: 'process_name == "bash"'
        action: "detect"
`), 0o644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	return path
}
