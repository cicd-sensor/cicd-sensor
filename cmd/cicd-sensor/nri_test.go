package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	nriobserver "github.com/cicd-sensor/cicd-sensor/internal/agent/nri"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestBuildNRIObserverOptions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	valid := nriOptions{
		NRISocket:   "/tmp/nri.sock",
		AgentSocket: "/tmp/agent.sock",
		Provider:    "github",
	}

	tests := []struct {
		name        string
		opts        nriOptions
		wantErrText string
	}{
		{name: "valid explicit options", opts: valid},
		{name: "missing nri socket", opts: withNRISocket(valid, ""), wantErrText: "nri socket path is required"},
		{name: "missing agent socket", opts: withAgentSocket(valid, ""), wantErrText: "agent socket path is required"},
		{name: "missing provider", opts: withNRIProvider(valid, ""), wantErrText: "nri provider must be github or gitlab"},
		{name: "unknown provider", opts: withNRIProvider(valid, "all"), wantErrText: "nri provider must be github or gitlab"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildNRIObserverOptions(tc.opts, logger)
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
				t.Fatalf("buildNRIObserverOptions: %v", err)
			}
			if got.SocketPath != tc.opts.NRISocket {
				t.Fatalf("socket path: got %q, want %q", got.SocketPath, tc.opts.NRISocket)
			}
			if got.AgentSocketPath != tc.opts.AgentSocket {
				t.Fatalf("agent socket path: got %q, want %q", got.AgentSocketPath, tc.opts.AgentSocket)
			}
			if got.Provider != jobcontext.Provider(tc.opts.Provider) {
				t.Fatalf("provider: got %q, want %q", got.Provider, tc.opts.Provider)
			}
			if got.Logger != logger {
				t.Fatal("logger was not preserved")
			}
		})
	}
}

func TestBuildNRIObserverOptions_DefaultSocketsRequireExplicitProvider(t *testing.T) {
	got, err := buildNRIObserverOptions(nriOptions{
		NRISocket:   nriobserver.DefaultSocketPath,
		AgentSocket: defaultSocketPath,
		Provider:    "gitlab",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildNRIObserverOptions default sockets: %v", err)
	}
	if got.SocketPath != "/var/run/nri/nri.sock" {
		t.Fatalf("socket path: got %q", got.SocketPath)
	}
	if got.AgentSocketPath != "/run/cicd-sensor/agent.sock" {
		t.Fatalf("agent socket path: got %q", got.AgentSocketPath)
	}
	if got.Provider != jobcontext.ProviderGitLab {
		t.Fatalf("provider: got %q", got.Provider)
	}
}

func withNRISocket(opts nriOptions, socket string) nriOptions {
	opts.NRISocket = socket
	return opts
}

func withAgentSocket(opts nriOptions, socket string) nriOptions {
	opts.AgentSocket = socket
	return opts
}

func withNRIProvider(opts nriOptions, provider string) nriOptions {
	opts.Provider = provider
	return opts
}
