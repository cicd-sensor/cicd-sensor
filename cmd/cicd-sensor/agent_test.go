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
