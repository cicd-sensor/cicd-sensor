package managerclient_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestManagerClient_FetchConfig_Success(t *testing.T) {
	svc := &fakeConfigService{
		handler: func(_ context.Context, req *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error) {
			if got := req.Header().Get("Authorization"); got != "Bearer "+testManagerToken {
				t.Fatalf("authorization: got %q, want %q", got, "Bearer "+testManagerToken)
			}
			if req.Msg.JobIdentity == nil || req.Msg.JobIdentity.ProjectPath != "acme/example" {
				t.Fatalf("project: got %v, want %q", req.Msg.JobIdentity, "acme/example")
			}
			sources := mustRuleSources(t, []rule.RuleSet{
				{
					RulesetID: "managed",
					Rules: []rule.Rule{
						{
							RuleID:    "detect-1",
							EventType: jobevent.ProcessExec,
							Condition: `process_name == "bash"`,
							Action:    rule.RuleActionDetect,
						},
					},
				},
			}, nil)
			return connect.NewResponse(&managerv1.FetchConfigResponse{
				Config: &managerv1.ServedConfig{
					ConfigRevision:          "sha256:test",
					DefaultMaxAlertsPerRule: 17,
					OutputSettings: &managerv1.OutputSettings{
						SummaryLog:      &managerv1.OutputSetting{Enabled: true},
						DetectionLog:    &managerv1.OutputSetting{Enabled: true},
						RuntimeEventLog: &managerv1.OutputSetting{Enabled: true},
					},
				},
				RuleSources: sources,
			}), nil
		},
	}
	server := newFakeConfigServer(t, svc)
	defer server.Close()

	client := mustManagerClient(t, server.URL)
	result, err := client.FetchConfig(context.Background(), &managerv1.FetchConfigRequest{
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
	})
	if err != nil {
		t.Fatalf("fetch config: %v", err)
	}
	if result.ConfigRevision != "sha256:test" {
		t.Fatalf("config_revision: got %q, want %q", result.ConfigRevision, "sha256:test")
	}
	if result.DefaultMaxAlertsPerRule != 17 {
		t.Fatalf("default_max_alerts_per_rule: got %d, want 17", result.DefaultMaxAlertsPerRule)
	}
	if result.OutputSettings == nil ||
		!result.OutputSettings.GetSummaryLog().GetEnabled() ||
		!result.OutputSettings.GetDetectionLog().GetEnabled() ||
		!result.OutputSettings.GetRuntimeEventLog().GetEnabled() {
		t.Fatalf("output_settings: got %+v, want all enabled", result.OutputSettings)
	}
	if len(result.RuleSources) != 1 {
		t.Fatalf("rule_sources: got %d, want 1", len(result.RuleSources))
	}
	ruleSets := result.RuleSources[0].RuleSets
	if len(ruleSets) != 1 {
		t.Fatalf("rule_sources[0].rule_sets: got %d, want 1", len(ruleSets))
	}
	if got := ruleSets[0].Rules[0].EventType; got != jobevent.ProcessExec {
		t.Fatalf("event_type: got %q, want %q", got, jobevent.ProcessExec)
	}
	if got := ruleSets[0].Rules[0].Action; got != rule.RuleActionDetect {
		t.Fatalf("action: got %q, want %q", got, rule.RuleActionDetect)
	}
}

func TestManagerClient_FetchConfig_PreservesOutputSettingPolicy(t *testing.T) {
	tests := []struct {
		name string
		in   *managerv1.OutputSetting
	}{
		{
			name: "nil remains nil",
		},
		{
			name: "explicit zero policy remains explicit",
			in:   &managerv1.OutputSetting{Enabled: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeConfigService{
				handler: func(context.Context, *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error) {
					return connect.NewResponse(&managerv1.FetchConfigResponse{
						Config: &managerv1.ServedConfig{
							OutputSettings: &managerv1.OutputSettings{
								DetectionLog: tt.in,
							},
						},
					}), nil
				},
			}
			server := newFakeConfigServer(t, svc)
			defer server.Close()

			client := mustManagerClient(t, server.URL)
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
			settings := result.OutputSettings
			if settings == nil {
				t.Fatal("output_settings: got nil")
			}
			if tt.in == nil {
				if settings.GetDetectionLog() != nil {
					t.Fatalf("detection_log: got %+v, want nil", settings.GetDetectionLog())
				}
				return
			}
			if settings.GetDetectionLog() == nil {
				t.Fatal("detection_log: got nil, want explicit zero policy")
			}
			if settings.GetDetectionLog().GetFlushThresholdBytes() != 0 ||
				settings.GetDetectionLog().GetFlushIntervalSeconds() != 0 {
				t.Fatalf("detection_log: got %+v, want all-zero policy", settings.GetDetectionLog())
			}
		})
	}
}

func TestManagerClient_FetchConfig_ServerError(t *testing.T) {
	svc := &fakeConfigService{
		handler: func(context.Context, *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error) {
			return nil, connect.NewError(connect.CodeInternal, errors.New("boom"))
		},
	}
	server := newFakeConfigServer(t, svc)
	defer server.Close()

	client := mustManagerClient(t, server.URL)
	_, err := client.FetchConfig(context.Background(), &managerv1.FetchConfigRequest{
		RunnerType: "machine",
		JobIdentity: &managerv1.JobIdentity{
			Provider:     "gitlab",
			ProviderHost: "gitlab.com",
			ProjectPath:  "group/project",
			GitlabJobId:  "123",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "internal") {
		t.Fatalf("fetch config error: got %v, want internal error", err)
	}
	var rpcErr *managerclient.RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("error type: got %T, want *managerclient.RPCError", err)
	}
	if rpcErr.Code != connect.CodeInternal {
		t.Fatalf("rpc code: got %v, want %v", rpcErr.Code, connect.CodeInternal)
	}
}

func TestManagerClient_FetchConfig_Unreachable(t *testing.T) {
	client := mustManagerClient(t, "http://127.0.0.1:1")
	_, err := client.FetchConfig(context.Background(), &managerv1.FetchConfigRequest{
		RunnerType: "machine",
		JobIdentity: &managerv1.JobIdentity{
			Provider:     "gitlab",
			ProviderHost: "gitlab.com",
			ProjectPath:  "group/project",
			GitlabJobId:  "123",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "fetch manager config") {
		t.Fatalf("fetch config error: got %v, want transport error", err)
	}
}

func TestManagerClient_FetchConfig_RejectsInvalidInput(t *testing.T) {
	t.Run("nil request", func(t *testing.T) {
		client := mustManagerClient(t, "https://manager.example.com")
		_, err := client.FetchConfig(context.Background(), nil)
		if err == nil || !strings.Contains(err.Error(), "fetch config request is nil") {
			t.Fatalf("error: got %v, want nil request error", err)
		}
	})

	t.Run("zero value client", func(t *testing.T) {
		var client managerclient.ConfigClient
		_, err := client.FetchConfig(context.Background(), &managerv1.FetchConfigRequest{})
		if err == nil || !strings.Contains(err.Error(), "manager client is nil") {
			t.Fatalf("error: got %v, want nil client error", err)
		}
	})

	t.Run("nil client", func(t *testing.T) {
		var client *managerclient.ConfigClient
		_, err := client.FetchConfig(context.Background(), &managerv1.FetchConfigRequest{})
		if err == nil || !strings.Contains(err.Error(), "manager client is nil") {
			t.Fatalf("error: got %v, want nil client error", err)
		}
	})
}

func TestManagerClient_FetchConfig_CanceledContext(t *testing.T) {
	svc := &fakeConfigService{
		handler: func(context.Context, *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error) {
			t.Fatal("handler should not run for an already-canceled request")
			return nil, nil
		},
	}
	server := newFakeConfigServer(t, svc)
	defer server.Close()

	client := mustManagerClient(t, server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.FetchConfig(ctx, &managerv1.FetchConfigRequest{})
	if err == nil {
		t.Fatal("expected canceled context error")
	}
	var rpcErr *managerclient.RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("error type: got %T, want *managerclient.RPCError", err)
	}
	if rpcErr.Code != connect.CodeCanceled {
		t.Fatalf("rpc code: got %v, want %v (err=%v)", rpcErr.Code, connect.CodeCanceled, err)
	}
}

func TestManagerClient_New_ValidatesConfig(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		token   string
		wantErr string
	}{
		{
			name:    "empty url",
			token:   testManagerToken,
			wantErr: "manager URL is required",
		},
		{
			name:    "unsupported scheme",
			baseURL: "ftp://manager.example.com",
			token:   testManagerToken,
			wantErr: "http or https",
		},
		{
			name:    "missing host",
			baseURL: "https:///manager",
			token:   testManagerToken,
			wantErr: "include a host",
		},
		{
			name:    "invalid token",
			baseURL: "https://manager.example.com",
			token:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wantErr: "sk_cs_",
		},
		{
			name:    "valid",
			baseURL: "https://manager.example.com",
			token:   testManagerToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := managerclient.NewConfigClient(testLogger, managerclient.Connection{
				BaseURL: tt.baseURL,
				Token:   tt.token,
			})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("New: got error %v, want nil", err)
				}
				if client == nil {
					t.Fatal("New: got nil client")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("New error: got %v, want containing %q", err, tt.wantErr)
			}
			if client != nil {
				t.Fatalf("New client: got %v, want nil", client)
			}
		})
	}
}

func TestManagerClient_New_WarnsOnHTTP(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		wantLog bool
	}{
		{name: "https stays silent", baseURL: "https://manager.example.com"},
		{name: "http localhost warns", baseURL: "http://localhost:8080", wantLog: true},
		{name: "http remote warns", baseURL: "http://manager.example.com", wantLog: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

			client, err := managerclient.NewConfigClient(logger, managerclient.Connection{
				BaseURL: tt.baseURL,
				Token:   testManagerToken,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if client == nil {
				t.Fatal("New: got nil client")
			}

			got := strings.Contains(logs.String(), "manager_url_insecure_scheme")
			if got != tt.wantLog {
				t.Fatalf("warning emitted: got %v, want %v; logs=%s", got, tt.wantLog, logs.String())
			}
		})
	}
}
