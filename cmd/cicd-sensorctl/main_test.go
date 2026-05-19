package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
)

func TestRunReportDispatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantErr    string
	}{
		{
			name:       "help",
			args:       []string{"help"},
			wantCode:   0,
			wantStdout: "cicd-sensorctl report attest",
		},
		{
			name:     "missing_subcommand",
			wantCode: 2,
			wantErr:  "report: subcommand is required",
		},
		{
			name:     "unknown_subcommand",
			args:     []string{"bogus"},
			wantCode: 2,
			wantErr:  "unknown report subcommand: bogus",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code, err := runReport(context.Background(), tt.args, nil, &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("exit code: got %d, want %d", code, tt.wantCode)
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("runReport: got error %v, want nil", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("runReport error: got %v, want containing %q", err, tt.wantErr)
				}
				var usageErr *cliUsageError
				if !errors.As(err, &usageErr) {
					t.Fatalf("error type: got %T, want *cliUsageError", err)
				}
			}
			if tt.wantStdout != "" && !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Fatalf("stdout: got %q, want containing %q", stdout.String(), tt.wantStdout)
			}
		})
	}
}

func TestRun_TokenGenerateHappyPath(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"token", "generate"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if !strings.HasPrefix(stdout.String(), managerauth.TokenPrefix) {
		t.Fatalf("stdout: got %q, want manager token", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr: got %q, want empty", stderr.String())
	}
}

func TestRunRuleDispatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantErr    string
	}{
		{
			name:       "help",
			args:       []string{"help"},
			wantCode:   0,
			wantStdout: "cicd-sensorctl rule validate",
		},
		{
			name:     "missing_subcommand",
			wantCode: 2,
			wantErr:  "rule: subcommand is required",
		},
		{
			name:     "unknown_subcommand",
			args:     []string{"bogus"},
			wantCode: 2,
			wantErr:  "unknown rule subcommand: bogus",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code, err := runRule(context.Background(), tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("exit code: got %d, want %d", code, tt.wantCode)
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("runRule: got error %v, want nil", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("runRule error: got %v, want containing %q", err, tt.wantErr)
				}
				var usageErr *cliUsageError
				if !errors.As(err, &usageErr) {
					t.Fatalf("error type: got %T, want *cliUsageError", err)
				}
			}
			if tt.wantStdout != "" && !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Fatalf("stdout: got %q, want containing %q", stdout.String(), tt.wantStdout)
			}
		})
	}
}
