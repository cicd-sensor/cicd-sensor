package main

import (
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/proxy/dockerd"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestBuildDockerdOptions(t *testing.T) {
	base := dockerd.Options{
		DockerDaemonSocket: "/tmp/upstream.sock",
		DockerProxySocket:  "/tmp/listen.sock",
		AgentSocket:        "/tmp/agent.sock",
	}

	tests := []struct {
		name        string
		provider    string
		want        jobcontext.Provider
		wantErrText string
	}{
		{name: "github provider", provider: "github", want: jobcontext.ProviderGitHub},
		{name: "gitlab provider", provider: "gitlab", want: jobcontext.ProviderGitLab},
		{name: "invalid provider is passed through", provider: "circle", want: jobcontext.Provider("circle")},
		{name: "missing provider", wantErrText: "provider is required"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildDockerdOptions(tc.provider, base)
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
				t.Fatalf("buildDockerdOptions: %v", err)
			}
			if got.Provider != tc.want {
				t.Fatalf("provider: got %q, want %q", got.Provider, tc.want)
			}
			if got.DockerDaemonSocket != base.DockerDaemonSocket {
				t.Fatalf("docker daemon socket: got %q, want %q", got.DockerDaemonSocket, base.DockerDaemonSocket)
			}
			if got.DockerProxySocket != base.DockerProxySocket {
				t.Fatalf("docker proxy socket: got %q, want %q", got.DockerProxySocket, base.DockerProxySocket)
			}
			if got.AgentSocket != base.AgentSocket {
				t.Fatalf("agent socket: got %q, want %q", got.AgentSocket, base.AgentSocket)
			}
		})
	}
}
