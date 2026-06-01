package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	nriobserver "github.com/cicd-sensor/cicd-sensor/internal/agent/nri"
)

func TestBuildNRIObserverOptions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	valid := nriOptions{
		NRISocket: "/tmp/nri.sock",
	}

	tests := []struct {
		name        string
		opts        nriOptions
		wantErrText string
	}{
		{name: "valid explicit options", opts: valid},
		{name: "missing nri socket", opts: withNRISocket(valid, ""), wantErrText: "nri socket path is required"},
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
			if got.Logger != logger {
				t.Fatal("logger was not preserved")
			}
		})
	}
}

func TestBuildNRIObserverOptions_DefaultValuesAreValid(t *testing.T) {
	got, err := buildNRIObserverOptions(nriOptions{
		NRISocket: nriobserver.DefaultSocketPath,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildNRIObserverOptions defaults: %v", err)
	}
	if got.SocketPath != "/var/run/nri/nri.sock" {
		t.Fatalf("socket path: got %q", got.SocketPath)
	}
}

func withNRISocket(opts nriOptions, socket string) nriOptions {
	opts.NRISocket = socket
	return opts
}
