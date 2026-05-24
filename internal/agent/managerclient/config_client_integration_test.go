package managerclient_test

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/manager"
	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
)

// TestManagerIntegration_FetchConfig_EndToEnd wires the real manager.Server
// to the real managerclient.ConfigClient over an httptest server. It exercises the
// full chain that unit tests elide: bearer token prefix on/off the wire,
// typed rule source delivery, output settings pass-through, and the downstream
// ApplyManagerConfig → ResolveRules step.
func TestManagerIntegration_FetchConfig_EndToEnd(t *testing.T) {
	managerToken := managerauth.TokenPrefix + strings.Repeat("a", 64)

	configDir := t.TempDir()
	rulesPath := filepath.Join(configDir, "rules.yaml")
	mustWriteFile(t, rulesPath, `
rule_sets:
  - ruleset_id: "managed"
    lists:
      shell_basenames:
        - "/bash"
        - "/sh"
    rules:
      - rule_id: "detect_bash"
        rule_name: "Shell executed"
        description: "Detects shell execution in CI jobs."
        event_type: "process_exec"
        condition: 'list.shell_basenames.exists(b, process.exec_path.endsWith(b))'
        action: "detect"
        max_alerts: 5
        tags:
          severity: "medium"
---
rule_modifiers:
  - modifier_id: "mod"
    targets:
      - ruleset_id: "managed"
        rule_id: "detect_bash"
    add_exceptions: 'process.exec_path.endsWith("/sh")'
`)
	served := &manager.ServedConfig{
		ConfigRevision:          "sha256:config",
		DefaultMaxAlertsPerRule: 23,
		OutputSettings: &managerv1.OutputSettings{
			SummaryLog:      &managerv1.OutputSetting{Enabled: true},
			DetectionLog:    &managerv1.OutputSetting{Enabled: true},
			RuntimeEventLog: &managerv1.OutputSetting{Enabled: true},
		},
	}

	srv := manager.NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), ":0", []string{managerToken}, served, rulesPath, nil, nil)
	ts := newFakeHTTPServer(t, srv.Handler())
	defer ts.Close()

	client, err := managerclient.NewConfigClient(testLogger, managerclient.Connection{BaseURL: ts.URL, Token: managerToken})
	if err != nil {
		t.Fatalf("new manager client: %v", err)
	}

	req := &managerv1.FetchConfigRequest{
		RunnerType: "machine",
		JobIdentity: &managerv1.JobIdentity{
			Provider:               "github",
			ProviderHost:           "github.com",
			ProjectPath:            "acme/example",
			GithubRunId:            "123",
			GithubJob:              "build",
			GithubRunAttempt:       "1",
			GithubRunnerTrackingId: "runner-1",
		},
	}

	result, err := client.FetchConfig(context.Background(), req)
	if err != nil {
		t.Fatalf("fetch config: %v", err)
	}

	if result.ConfigRevision != served.ConfigRevision {
		t.Fatalf("config_revision: got %q, want %q", result.ConfigRevision, served.ConfigRevision)
	}
	if result.DefaultMaxAlertsPerRule != 23 {
		t.Fatalf("default_max_alerts_per_rule: got %d, want 23", result.DefaultMaxAlertsPerRule)
	}
	if len(result.RuleSources) != 2 {
		t.Fatalf("rule_sources: got %d, want 2", len(result.RuleSources))
	}
	ruleSets := result.RuleSources[1].RuleSets
	if len(ruleSets) != 1 {
		t.Fatalf("rule_sources[1].rule_sets: got %d, want 1", len(ruleSets))
	}
	if got := ruleSets[0].Rules[0].RuleID; got != "detect_bash" {
		t.Fatalf("rule_id: got %q, want detect_bash", got)
	}
	if got := ruleSets[0].Rules[0].EventType; got != jobevent.ProcessExec {
		t.Fatalf("event_type: got %q, want %q", got, jobevent.ProcessExec)
	}
	ruleModifiers := result.RuleSources[1].RuleModifiers
	if len(ruleModifiers) != 1 {
		t.Fatalf("rule_sources[1].rule_modifiers: got %d, want 1", len(ruleModifiers))
	}
	if !result.OutputSettings.GetSummaryLog().GetEnabled() {
		t.Fatal("output_settings.summary_log.enabled: got false, want true")
	}

	// Downstream: ApplyManagerConfig must resolve the delivered rules.
	scope := jobscope.NewHost()
	if err := scope.ApplyManagerConfig(jobscope.ManagerConfig{
		RuleSources:             result.RuleSources,
		ConfigRevision:          result.ConfigRevision,
		OutputSettings:          result.OutputSettings,
		DefaultMaxAlertsPerRule: result.DefaultMaxAlertsPerRule,
	}); err != nil {
		t.Fatalf("ApplyManagerConfig: %v", err)
	}
	scope.ResolveRules(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"))
	if scope.DefaultMaxAlertsPerRule != 23 {
		t.Fatalf("scope default_max_alerts_per_rule: got %d, want 23", scope.DefaultMaxAlertsPerRule)
	}
	if !resolvedRulesContain(scope, "detect_bash") {
		t.Fatalf("resolved rules do not contain detect_bash")
	}
	if !scope.OutputSettings.GetSummaryLog().GetEnabled() {
		t.Fatal("expected scope to store output settings from manager response")
	}
}

// TestManagerIntegration_FetchConfig_RejectsBadToken verifies the Connect
// auth interceptor wires the 401 through the real client.
func TestManagerIntegration_FetchConfig_RejectsBadToken(t *testing.T) {
	good := managerauth.TokenPrefix + strings.Repeat("a", 64)
	bad := managerauth.TokenPrefix + strings.Repeat("b", 64)

	configDir := t.TempDir()
	mustWriteFile(t, filepath.Join(configDir, "manager.yaml"), "bind:\n  address: 127.0.0.1\n  port: 0\n")
	srv := manager.NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), ":0", []string{good}, &manager.ServedConfig{}, "", nil, nil)
	ts := newFakeHTTPServer(t, srv.Handler())
	defer ts.Close()

	client, err := managerclient.NewConfigClient(testLogger, managerclient.Connection{BaseURL: ts.URL, Token: bad})
	if err != nil {
		t.Fatalf("new manager client: %v", err)
	}
	_, err = client.FetchConfig(context.Background(), &managerv1.FetchConfigRequest{
		JobIdentity: &managerv1.JobIdentity{
			Provider:               "github",
			ProviderHost:           "github.com",
			ProjectPath:            "acme/example",
			GithubRunId:            "123",
			GithubJob:              "build",
			GithubRunAttempt:       "1",
			GithubRunnerTrackingId: "runner-1",
		},
	})
	if err == nil {
		t.Fatal("expected auth failure")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("error code: got %v, want %v (err=%v)", got, connect.CodeUnauthenticated, err)
	}
}

// TestManagerIntegration_FetchConfig_RejectsInvalidIdentity verifies the
// server-side JobIdentity.Validate() gate.
func TestManagerIntegration_FetchConfig_RejectsInvalidIdentity(t *testing.T) {
	managerToken := managerauth.TokenPrefix + strings.Repeat("a", 64)

	configDir := t.TempDir()
	mustWriteFile(t, filepath.Join(configDir, "manager.yaml"), "bind:\n  address: 127.0.0.1\n  port: 0\n")
	srv := manager.NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), ":0", []string{managerToken}, &manager.ServedConfig{}, "", nil, nil)
	ts := newFakeHTTPServer(t, srv.Handler())
	defer ts.Close()

	client, err := managerclient.NewConfigClient(testLogger, managerclient.Connection{BaseURL: ts.URL, Token: managerToken})
	if err != nil {
		t.Fatalf("new manager client: %v", err)
	}
	// Empty identity triggers server-side CodeInvalidArgument.
	_, err = client.FetchConfig(context.Background(), &managerv1.FetchConfigRequest{})
	if err == nil {
		t.Fatal("expected invalid argument error")
	}
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("error code: got %v, want %v (err=%v)", got, connect.CodeInvalidArgument, err)
	}
}

// TestManagerIntegration_FetchConfig_EmptyBundle verifies that an empty local
// rule tree still receives the baseline rules from the manager.
func TestManagerIntegration_FetchConfig_EmptyBundle(t *testing.T) {
	managerToken := managerauth.TokenPrefix + strings.Repeat("a", 64)

	configDir := t.TempDir()
	mustWriteFile(t, filepath.Join(configDir, "manager.yaml"), "bind:\n  address: 127.0.0.1\n  port: 0\n")
	srv := manager.NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), ":0", []string{managerToken}, &manager.ServedConfig{}, "", nil, nil)
	ts := newFakeHTTPServer(t, srv.Handler())
	defer ts.Close()

	client, err := managerclient.NewConfigClient(testLogger, managerclient.Connection{BaseURL: ts.URL, Token: managerToken})
	if err != nil {
		t.Fatalf("new manager client: %v", err)
	}
	result, err := client.FetchConfig(context.Background(), &managerv1.FetchConfigRequest{
		JobIdentity: &managerv1.JobIdentity{
			Provider:               "github",
			ProviderHost:           "github.com",
			ProjectPath:            "acme/example",
			GithubRunId:            "123",
			GithubJob:              "build",
			GithubRunAttempt:       "1",
			GithubRunnerTrackingId: "runner-1",
		},
	})
	if err != nil {
		t.Fatalf("fetch config: %v", err)
	}
	if len(result.RuleSources) != 1 {
		t.Fatalf("rule_sources: got %d, want 1 baseline source", len(result.RuleSources))
	}
	if len(result.RuleSources[0].RuleSets) == 0 {
		t.Fatal("expected baseline rule sets")
	}
}

func resolvedRulesContain(scope *jobscope.JobScopeState, ruleID string) bool {
	for _, resolved := range scope.ResolvedRules.Rules {
		if resolved.Rule.RuleID == ruleID {
			return true
		}
	}
	return false
}
