package main

import (
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
)

func TestValidateAgentStartRequiredOptions(t *testing.T) {
	valid := agentStartOptions{
		Provider:      "github",
		Runner:        "machine",
		ShutdownGrace: time.Second,
	}

	tests := []struct {
		name        string
		opts        agentStartOptions
		wantErrText string
	}{
		{name: "github machine", opts: valid},
		{
			name: "gitlab kubernetes",
			opts: agentStartOptions{
				Provider:      "gitlab",
				Runner:        "kubernetes",
				ShutdownGrace: time.Second,
			},
		},
		{
			name:        "missing provider",
			opts:        withAgentProvider(valid, ""),
			wantErrText: "provider is required",
		},
		{
			name:        "unsupported provider",
			opts:        withAgentProvider(valid, "circle"),
			wantErrText: "provider must be github or gitlab",
		},
		{
			name:        "missing runner",
			opts:        withAgentRunner(valid, ""),
			wantErrText: "runner is required",
		},
		{
			name:        "unsupported runner",
			opts:        withAgentRunner(valid, "container"),
			wantErrText: "runner must be machine or kubernetes",
		},
		{
			name:        "non-positive shutdown grace",
			opts:        withAgentShutdownGrace(valid, 0),
			wantErrText: "shutdown-grace must be positive",
		},
		{
			name:        "github k8s runner socket outside github kubernetes",
			opts:        withGitHubK8sRunnerSocket(valid, "/tmp/runner.sock"),
			wantErrText: "github k8s runner socket is only valid with provider github and runner kubernetes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAgentStartRequiredOptions(tc.opts)
			if tc.wantErrText == "" {
				if err != nil {
					t.Fatalf("validateAgentStartRequiredOptions: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantErrText) {
				t.Fatalf("error: got %q, want substring %q", err.Error(), tc.wantErrText)
			}
		})
	}
}

func TestValidateAgentStartOptionsRequiresManagerToken(t *testing.T) {
	opts := agentStartOptions{
		Provider:      "github",
		Runner:        "machine",
		ShutdownGrace: time.Second,
	}

	if err := validateAgentStartOptions(opts); err != nil {
		t.Fatalf("validateAgentStartOptions without manager: %v", err)
	}

	opts.ManagerURL = "https://manager.example.com"
	err := validateAgentStartOptions(opts)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "manager token is required") {
		t.Fatalf("error: got %q", err.Error())
	}

	opts.ManagerToken = managerauth.TokenPrefix + strings.Repeat("a", 64)
	if err := validateAgentStartOptions(opts); err != nil {
		t.Fatalf("validateAgentStartOptions: %v", err)
	}
}

func TestValidateAgentStartOptionsRequiresManagerForKubernetes(t *testing.T) {
	opts := agentStartOptions{
		Provider:      "github",
		Runner:        "kubernetes",
		ShutdownGrace: time.Second,
	}

	err := validateAgentStartOptions(opts)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "manager-url is required for runner kubernetes") {
		t.Fatalf("error: got %q", err.Error())
	}

	opts.ManagerURL = "https://manager.example.com"
	opts.ManagerToken = managerauth.TokenPrefix + strings.Repeat("a", 64)
	if err := validateAgentStartOptions(opts); err != nil {
		t.Fatalf("validateAgentStartOptions: %v", err)
	}
}

func TestResolveAgentStartOptions(t *testing.T) {
	valid := agentStartOptions{
		Provider:      "github",
		Runner:        "kubernetes",
		ShutdownGrace: time.Second,
	}
	tests := []struct {
		name       string
		opts       agentStartOptions
		wantSocket string
		wantErr    string
	}{
		{
			name:       "github kubernetes uses default runner socket",
			opts:       valid,
			wantSocket: defaultGitHubK8sRunnerSocketPath,
		},
		{
			name:       "github kubernetes keeps explicit runner socket",
			opts:       withGitHubK8sRunnerSocket(valid, "/tmp/runner.sock"),
			wantSocket: "/tmp/runner.sock",
		},
		{
			name:    "github machine rejects runner socket",
			opts:    withAgentRunner(withGitHubK8sRunnerSocket(valid, "/tmp/runner.sock"), "machine"),
			wantErr: "github k8s runner socket is only valid with provider github and runner kubernetes",
		},
		{
			name:    "gitlab kubernetes rejects runner socket",
			opts:    withAgentProvider(withGitHubK8sRunnerSocket(valid, "/tmp/runner.sock"), "gitlab"),
			wantErr: "github k8s runner socket is only valid with provider github and runner kubernetes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveAgentStartOptions(tc.opts)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error: got %q, want substring %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveAgentStartOptions: %v", err)
			}
			if got.GitHubK8sRunnerSocketPath != tc.wantSocket {
				t.Fatalf("github k8s runner socket: got %q, want %q", got.GitHubK8sRunnerSocketPath, tc.wantSocket)
			}
		})
	}
}

func withAgentProvider(opts agentStartOptions, provider string) agentStartOptions {
	opts.Provider = provider
	return opts
}

func withAgentRunner(opts agentStartOptions, runner string) agentStartOptions {
	opts.Runner = runner
	return opts
}

func withAgentShutdownGrace(opts agentStartOptions, shutdownGrace time.Duration) agentStartOptions {
	opts.ShutdownGrace = shutdownGrace
	return opts
}

func withGitHubK8sRunnerSocket(opts agentStartOptions, socketPath string) agentStartOptions {
	opts.GitHubK8sRunnerSocketPath = socketPath
	return opts
}
