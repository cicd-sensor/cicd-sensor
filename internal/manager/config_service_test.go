package manager

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1/managerv1connect"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

var testManagerSecret = managerauth.TokenPrefix + strings.Repeat("a", 64)
var testManagerTokens = []string{testManagerSecret}

type fakeBaselineRuleSource struct {
	rules    rulesource.LoadedRules
	err      error
	provider string
}

func (s *fakeBaselineRuleSource) LoadForProvider(ctx context.Context, logger *slog.Logger, provider string) (rulesource.LoadedRules, error) {
	s.provider = provider
	return s.rules, s.err
}

func TestConfigService_FetchConfig(t *testing.T) {
	validIdentity := &managerv1.JobIdentity{
		Provider:               "github",
		ProviderHost:           "github.com",
		ProjectPath:            "acme/example",
		GithubRunId:            "123",
		GithubJob:              "build",
		GithubRunAttempt:       "1",
		GithubRunnerTrackingId: "runner-1",
	}
	unsupportedProviderIdentity := proto.Clone(validIdentity).(*managerv1.JobIdentity)
	unsupportedProviderIdentity.Provider = "bitbucket"
	emptyProviderIdentity := proto.Clone(validIdentity).(*managerv1.JobIdentity)
	emptyProviderIdentity.Provider = ""

	tests := []struct {
		name         string
		token        string
		req          *managerv1.FetchConfigRequest
		ruleFiles    map[string]string
		startupYAML  string
		wantCode     connect.Code
		wantRuleSets int
		wantManager  bool
		wantDefault  int32
	}{
		{
			name:  "valid request returns cached config response",
			token: testManagerSecret,
			req:   &managerv1.FetchConfigRequest{JobIdentity: validIdentity},
			ruleFiles: map[string]string{
				"set.yaml": `
rule_sets:
  - ruleset_id: "global-set"
    rules:
      - rule_id: "detect_bash"
        event_type: "process_exec"
        condition: 'process_name == "bash"'
        action: "detect"
`,
			},
			startupYAML: `
bind:
  address: 127.0.0.1
  port: 0
default_max_alerts_per_rule: 25
sinks:
  test-sink:
    type: gcs
    uri: gs://test-bucket
logs:
  summary_log:
    sink: test-sink
`,
			wantRuleSets: 2,
			wantManager:  true,
			wantDefault:  25,
		},
		{
			name:      "baseline response is allowed when no rules file is configured",
			token:     testManagerSecret,
			req:       &managerv1.FetchConfigRequest{JobIdentity: validIdentity},
			ruleFiles: map[string]string{},
			startupYAML: `
bind:
  address: 127.0.0.1
  port: 0
`,
			wantRuleSets: 1,
		},
		{
			name:     "token mismatch returns unauthenticated",
			token:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			req:      &managerv1.FetchConfigRequest{JobIdentity: validIdentity},
			wantCode: connect.CodeUnauthenticated,
		},
		{
			name:     "missing token returns unauthenticated",
			token:    "",
			req:      &managerv1.FetchConfigRequest{JobIdentity: validIdentity},
			wantCode: connect.CodeUnauthenticated,
		},
		{
			name:     "invalid job identity returns invalid_argument",
			token:    testManagerSecret,
			req:      &managerv1.FetchConfigRequest{},
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "unsupported provider returns invalid_argument",
			token:    testManagerSecret,
			req:      &managerv1.FetchConfigRequest{JobIdentity: unsupportedProviderIdentity},
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "empty provider returns invalid_argument",
			token:    testManagerSecret,
			req:      &managerv1.FetchConfigRequest{JobIdentity: emptyProviderIdentity},
			wantCode: connect.CodeInvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			startupPath := filepath.Join(dir, "manager.yaml")
			startupContent := tt.startupYAML
			if startupContent == "" {
				startupContent = "bind:\n  address: 127.0.0.1\n  port: 0\n"
			}
			if err := os.WriteFile(startupPath, []byte(startupContent), 0o644); err != nil {
				t.Fatalf("write startup config: %v", err)
			}
			startupCfg, err := LoadStartupConfig(startupPath)
			if err != nil {
				t.Fatalf("load startup config: %v", err)
			}
			config := &ServedConfig{
				ConfigRevision:          startupCfg.Revision,
				DefaultMaxAlertsPerRule: startupCfg.DefaultMaxAlertsPerRule,
			}
			var rulesPath string
			if len(tt.ruleFiles) > 0 {
				rulesPath = writeManagerRuleBundle(t, dir, tt.ruleFiles)
			}
			if startupCfg.Logs["summary_log"].Sink != "" {
				config.OutputSettings = &managerv1.OutputSettings{
					SummaryLog: &managerv1.OutputSetting{
						Enabled:              true,
						FlushThresholdBytes:  1,
						FlushIntervalSeconds: 1,
					},
				}
			}

			server := NewServer(testLogger, ":0", testManagerTokens, config, rulesPath, &startupCfg, nil)
			server.baselineRules = &fakeBaselineRuleSource{
				rules: rulesource.LoadedRules{
					RuleSets: []rule.RuleSet{{
						RulesetID: "baseline-set",
						Revision:  "v20260519-001",
						Rules: []rule.Rule{{
							RuleID:    "baseline_detect",
							EventType: "process_exec",
							Condition: `process_name == "true"`,
							Action:    rule.RuleActionDetect,
						}},
					}},
				},
			}
			ts := newManagerHTTPTestServer(t, server.httpServer.Handler)
			defer ts.Close()

			client := managerv1connect.NewConfigServiceClient(ts.Client(), ts.URL)

			connectReq := connect.NewRequest(tt.req)
			if tt.token != "" {
				connectReq.Header().Set("Authorization", managerBearer(tt.token))
			}

			resp, err := client.FetchConfig(context.Background(), connectReq)

			if tt.wantCode != 0 {
				if err == nil {
					t.Fatalf("expected error with code %v, got nil", tt.wantCode)
				}
				if got := connect.CodeOf(err); got != tt.wantCode {
					t.Fatalf("error code: got %v, want %v (err=%v)", got, tt.wantCode, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("fetch config: %v", err)
			}
			var sets []rule.RuleSet
			for _, source := range protoconv.FromProtoRuleSources(resp.Msg.RuleSources) {
				sets = append(sets, source.RuleSets...)
			}
			if got := len(sets); got != tt.wantRuleSets {
				t.Fatalf("rule_sets: got %d, want %d", got, tt.wantRuleSets)
			}
			if len(tt.ruleFiles) > 0 {
				if got := sets[len(sets)-1].Revision; !strings.HasPrefix(got, "sha256:") {
					t.Fatalf("last rule set revision: got %q, want sha256 revision", got)
				}
			}
			if resp.Msg.GetConfig().GetDefaultMaxAlertsPerRule() != tt.wantDefault {
				t.Fatalf("default_max_alerts_per_rule: got %d, want %d", resp.Msg.GetConfig().GetDefaultMaxAlertsPerRule(), tt.wantDefault)
			}
			hasManager := resp.Msg.GetConfig().GetOutputSettings().GetSummaryLog().GetEnabled()
			if hasManager != tt.wantManager {
				t.Fatalf("manager output: got %v, want %v", hasManager, tt.wantManager)
			}
			if tt.wantManager {
				assertSummaryOutputSettings(t, resp.Msg.GetConfig().GetOutputSettings())
			} else if got := resp.Msg.GetConfig().GetOutputSettings(); got != nil {
				t.Fatalf("output_settings: got %+v, want nil when output is disabled", got)
			}
		})
	}
}

func TestConfigService_FetchConfig_PrependsBaselineRules(t *testing.T) {
	baselineRules := &fakeBaselineRuleSource{
		rules: rulesource.LoadedRules{
			RuleSets: []rule.RuleSet{{
				RulesetID: "baseline-set",
				Revision:  "v20260519-001",
				Rules: []rule.Rule{{
					RuleID:    "baseline_detect",
					EventType: "process_exec",
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
				}},
			}},
		},
	}

	dir := t.TempDir()
	rulesPath := writeManagerRuleBundle(t, dir, map[string]string{
		"manual.yaml": `
rule_sets:
  - ruleset_id: "manual-set"
    rules:
      - rule_id: "manual_detect"
        event_type: "process_exec"
        condition: 'process_name == "sh"'
        action: "detect"
`,
	})
	server := NewServer(testLogger, ":0", testManagerTokens, &ServedConfig{
		ConfigRevision: "rev",
	}, rulesPath, &StartupConfig{}, nil)
	server.baselineRules = baselineRules
	ts := newManagerHTTPTestServer(t, server.httpServer.Handler)
	defer ts.Close()

	client := managerv1connect.NewConfigServiceClient(ts.Client(), ts.URL)
	req := connect.NewRequest(&managerv1.FetchConfigRequest{JobIdentity: &managerv1.JobIdentity{
		Provider:               "github",
		ProviderHost:           "github.com",
		ProjectPath:            "acme/example",
		GithubRunId:            "123",
		GithubJob:              "build",
		GithubRunAttempt:       "1",
		GithubRunnerTrackingId: "runner-1",
	}})
	req.Header().Set("Authorization", managerBearer(testManagerSecret))

	resp, err := client.FetchConfig(context.Background(), req)
	if err != nil {
		t.Fatalf("fetch config: %v", err)
	}
	if baselineRules.provider != "github" {
		t.Fatalf("baseline provider: got %q, want github", baselineRules.provider)
	}
	sources := protoconv.FromProtoRuleSources(resp.Msg.RuleSources)
	if got := len(sources); got != 2 {
		t.Fatalf("rule sources: got %d, want 2", got)
	}
	if got := sources[0].RuleSets[0].RulesetID; got != "baseline-set" {
		t.Fatalf("first ruleset: got %q, want baseline-set", got)
	}
	if got := sources[1].RuleSets[0].RulesetID; got != "manual-set" {
		t.Fatalf("second ruleset: got %q, want manual-set", got)
	}
}

func TestConfigService_FetchConfig_BaselineFailureReturnsUnavailable(t *testing.T) {
	server := NewServer(testLogger, ":0", testManagerTokens, &ServedConfig{
		ConfigRevision: "rev",
	}, "", &StartupConfig{}, nil)
	server.baselineRules = &fakeBaselineRuleSource{err: errors.New("registry unavailable")}
	ts := newManagerHTTPTestServer(t, server.httpServer.Handler)
	defer ts.Close()

	client := managerv1connect.NewConfigServiceClient(ts.Client(), ts.URL)
	req := connect.NewRequest(&managerv1.FetchConfigRequest{JobIdentity: &managerv1.JobIdentity{
		Provider:               "github",
		ProviderHost:           "github.com",
		ProjectPath:            "acme/example",
		GithubRunId:            "123",
		GithubJob:              "build",
		GithubRunAttempt:       "1",
		GithubRunnerTrackingId: "runner-1",
	}})
	req.Header().Set("Authorization", managerBearer(testManagerSecret))

	_, err := client.FetchConfig(context.Background(), req)
	if got := connect.CodeOf(err); got != connect.CodeUnavailable {
		t.Fatalf("code: got %v, want %v (err=%v)", got, connect.CodeUnavailable, err)
	}
}

func TestConfigService_FetchConfig_ReloadsLocalRulesOnChange(t *testing.T) {
	dir := t.TempDir()
	rulesPath := writeManagerRuleBundle(t, dir, map[string]string{
		"rules.yaml": `
rule_sets:
  - ruleset_id: "initial-set"
    rules:
      - rule_id: "initial_detect"
        event_type: "process_exec"
        condition: 'process_name == "bash"'
        action: "detect"
`,
	})
	server := NewServer(testLogger, ":0", testManagerTokens, &ServedConfig{
		ConfigRevision: "rev",
	}, rulesPath, &StartupConfig{}, nil)
	ts := newManagerHTTPTestServer(t, server.httpServer.Handler)
	defer ts.Close()

	client := managerv1connect.NewConfigServiceClient(ts.Client(), ts.URL)
	req := connect.NewRequest(&managerv1.FetchConfigRequest{JobIdentity: &managerv1.JobIdentity{
		Provider:               "github",
		ProviderHost:           "github.com",
		ProjectPath:            "acme/example",
		GithubRunId:            "123",
		GithubJob:              "build",
		GithubRunAttempt:       "1",
		GithubRunnerTrackingId: "runner-1",
	}})
	req.Header().Set("Authorization", managerBearer(testManagerSecret))

	first, err := client.FetchConfig(context.Background(), req)
	if err != nil {
		t.Fatalf("initial fetch config: %v", err)
	}
	assertRuleSetIDAt(t, first.Msg.RuleSources, 1, "initial-set")

	if err := os.WriteFile(rulesPath, []byte(`
rule_sets:
  - ruleset_id: "updated-set"
    rules:
      - rule_id: "updated_detect"
        event_type: "process_exec"
        condition: 'process_name == "sh"'
        action: "detect"
`), 0o644); err != nil {
		t.Fatalf("update rules: %v", err)
	}

	secondReq := connect.NewRequest(proto.Clone(req.Msg).(*managerv1.FetchConfigRequest))
	secondReq.Header().Set("Authorization", managerBearer(testManagerSecret))
	second, err := client.FetchConfig(context.Background(), secondReq)
	if err != nil {
		t.Fatalf("updated fetch config: %v", err)
	}
	assertRuleSetIDAt(t, second.Msg.RuleSources, 1, "updated-set")
}

func TestConfigService_FetchConfig_LocalRulesFailureReturnsUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-rules.yaml")
	server := NewServer(testLogger, ":0", testManagerTokens, &ServedConfig{
		ConfigRevision: "rev",
	}, path, &StartupConfig{}, nil)
	ts := newManagerHTTPTestServer(t, server.httpServer.Handler)
	defer ts.Close()

	client := managerv1connect.NewConfigServiceClient(ts.Client(), ts.URL)
	req := connect.NewRequest(&managerv1.FetchConfigRequest{JobIdentity: &managerv1.JobIdentity{
		Provider:               "github",
		ProviderHost:           "github.com",
		ProjectPath:            "acme/example",
		GithubRunId:            "123",
		GithubJob:              "build",
		GithubRunAttempt:       "1",
		GithubRunnerTrackingId: "runner-1",
	}})
	req.Header().Set("Authorization", managerBearer(testManagerSecret))

	_, err := client.FetchConfig(context.Background(), req)
	if got := connect.CodeOf(err); got != connect.CodeUnavailable {
		t.Fatalf("code: got %v, want %v (err=%v)", got, connect.CodeUnavailable, err)
	}
}

func writeManagerRuleBundle(t *testing.T, dir string, ruleFiles map[string]string) string {
	t.Helper()

	var body strings.Builder
	first := true
	for _, content := range ruleFiles {
		if !first {
			body.WriteString("\n---\n")
		}
		first = false
		body.WriteString(content)
	}
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(body.String()), 0o644); err != nil {
		t.Fatalf("write rules bundle: %v", err)
	}
	return path
}

func assertRuleSetIDAt(t *testing.T, sources []*managerv1.RuleSource, index int, want string) {
	t.Helper()
	loaded := protoconv.FromProtoRuleSources(sources)
	if len(loaded) <= index || len(loaded[index].RuleSets) == 0 {
		t.Fatalf("rule sources: got %+v, want ruleset %q at index %d", loaded, want, index)
	}
	if got := loaded[index].RuleSets[0].RulesetID; got != want {
		t.Fatalf("ruleset at index %d: got %q, want %q", index, got, want)
	}
}

func assertSummaryOutputSettings(t *testing.T, got *managerv1.OutputSettings) {
	t.Helper()
	if got == nil {
		t.Fatal("output_settings: got nil")
	}
	if got.GetDetectionLog().GetEnabled() ||
		got.GetDetectionLog().GetFlushThresholdBytes() != 0 ||
		got.GetDetectionLog().GetFlushIntervalSeconds() != 0 {
		t.Fatalf("detection_log output setting: got %+v", got.GetDetectionLog())
	}
	if got.GetRuntimeEventLog().GetEnabled() ||
		got.GetRuntimeEventLog().GetFlushThresholdBytes() != 0 ||
		got.GetRuntimeEventLog().GetFlushIntervalSeconds() != 0 {
		t.Fatalf("runtime_event_log output setting: got %+v", got.GetRuntimeEventLog())
	}
	if !got.GetSummaryLog().GetEnabled() ||
		got.GetSummaryLog().GetFlushThresholdBytes() != 1 ||
		got.GetSummaryLog().GetFlushIntervalSeconds() != 1 {
		t.Fatalf("summary_log output setting: got %+v", got.GetSummaryLog())
	}
}

func TestAuthInterceptor_EmitsAuditLogOnFailure(t *testing.T) {
	var buf bytes.Buffer
	auditLogger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manager.yaml"), []byte("bind:\n  address: 127.0.0.1\n  port: 0\n"), 0o644); err != nil {
		t.Fatalf("write startup config: %v", err)
	}
	startupCfg, err := LoadStartupConfig(filepath.Join(dir, "manager.yaml"))
	if err != nil {
		t.Fatalf("load startup config: %v", err)
	}
	server := NewServer(auditLogger, ":0", testManagerTokens, &ServedConfig{ConfigRevision: startupCfg.Revision}, "", &startupCfg, nil)
	ts := newManagerHTTPTestServer(t, server.httpServer.Handler)
	defer ts.Close()

	client := managerv1connect.NewConfigServiceClient(ts.Client(), ts.URL)
	connectReq := connect.NewRequest(&managerv1.FetchConfigRequest{
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
	if _, err := client.FetchConfig(context.Background(), connectReq); err == nil {
		t.Fatal("expected unauthenticated error")
	}

	if !strings.Contains(buf.String(), "manager_auth_failed") {
		t.Fatalf("audit log missing event manager_auth_failed: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "FetchConfig") {
		t.Fatalf("audit log missing procedure name FetchConfig: %s", buf.String())
	}
}

func TestCollectorService_MountedBehindAuth(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manager.yaml"), []byte("bind:\n  address: 127.0.0.1\n  port: 0\n"), 0o644); err != nil {
		t.Fatalf("write startup config: %v", err)
	}
	startupCfg, err := LoadStartupConfig(filepath.Join(dir, "manager.yaml"))
	if err != nil {
		t.Fatalf("load startup config: %v", err)
	}
	server := NewServer(testLogger, ":0", testManagerTokens, &ServedConfig{ConfigRevision: startupCfg.Revision}, "", &startupCfg, nil)
	ts := newManagerHTTPTestServer(t, server.httpServer.Handler)
	defer ts.Close()

	client := managerv1connect.NewCollectorServiceClient(ts.Client(), ts.URL)
	req := connect.NewRequest(&managerv1.IngestLogRequest{})
	if _, err := client.IngestLog(context.Background(), req); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("missing token code: got %v, want %v (err=%v)", connect.CodeOf(err), connect.CodeUnauthenticated, err)
	}

	req = connect.NewRequest(&managerv1.IngestLogRequest{})
	req.Header().Set("Authorization", managerBearer(testManagerSecret))
	if _, err := client.IngestLog(context.Background(), req); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("valid token code: got %v, want %v (err=%v)", connect.CodeOf(err), connect.CodeInvalidArgument, err)
	}
}
