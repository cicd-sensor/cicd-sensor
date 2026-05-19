package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
)

func TestRunTokenGenerate_OutputShape(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code, err := runTokenGenerate(context.Background(), nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runTokenGenerate: unexpected error: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("stderr: got %q, want empty", got)
	}

	got := stdout.String()
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("stdout: missing trailing newline, got %q", got)
	}
	token := strings.TrimRight(got, "\n")

	if !strings.HasPrefix(token, managerauth.TokenPrefix) {
		t.Fatalf("token: missing %q prefix, got %q", managerauth.TokenPrefix, token)
	}

	secret := strings.TrimPrefix(token, managerauth.TokenPrefix)
	if len(secret) != tokenSecretBytes*2 {
		t.Fatalf("secret length: got %d, want %d", len(secret), tokenSecretBytes*2)
	}
	if _, err := hex.DecodeString(secret); err != nil {
		t.Fatalf("secret is not lowercase hex: %v (secret=%q)", err, secret)
	}
	for _, r := range secret {
		if r >= 'A' && r <= 'Z' {
			t.Fatalf("secret contains uppercase hex: %q", secret)
		}
	}

	// The generated token must satisfy the manager's validator so it can be
	// used directly as CICD_SENSOR_MANAGER_TOKEN.
	if !managerauth.IsValidToken(token) {
		t.Fatalf("managerauth.IsValidToken rejected generated token")
	}
}

func TestRunTokenGenerate_Uniqueness(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 8)
	for i := range 8 {
		var stdout, stderr bytes.Buffer
		if _, err := runTokenGenerate(context.Background(), nil, &stdout, &stderr); err != nil {
			t.Fatalf("iteration %d: runTokenGenerate: %v", i, err)
		}
		token := strings.TrimRight(stdout.String(), "\n")
		if _, dup := seen[token]; dup {
			t.Fatalf("duplicate token generated across runs: %q", token)
		}
		seen[token] = struct{}{}
	}
}

func TestRunTokenGenerate_Help(t *testing.T) {
	t.Parallel()

	tests := []string{"-h", "--help"}
	for _, arg := range tests {
		t.Run(arg, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code, err := runTokenGenerate(context.Background(), []string{arg}, &stdout, &stderr)
			if err != nil {
				t.Fatalf("runTokenGenerate: unexpected error: %v", err)
			}
			if code != 0 {
				t.Fatalf("exit code: got %d, want 0", code)
			}
			got := stdout.String() + stderr.String()
			if !strings.Contains(got, "cicd-sensorctl token generate") {
				t.Fatalf("help output: stdout=%q stderr=%q, want substring", stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunTokenGenerate_UnexpectedArg(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code, err := runTokenGenerate(context.Background(), []string{"extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code: got %d, want 2", code)
	}
	if err == nil {
		t.Fatalf("expected usage error, got nil")
	}
	var usageErr *cliUsageError
	if !errors.As(err, &usageErr) {
		t.Fatalf("error type: got %T, want *cliUsageError", err)
	}
	if !strings.Contains(err.Error(), "unexpected positional arguments") {
		t.Fatalf("error message: got %q, want substring", err.Error())
	}
}

func TestRunToken_Dispatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "help",
			args:       []string{"help"},
			wantCode:   0,
			wantStdout: "cicd-sensorctl token generate",
		},
		{
			name:       "missing_subcommand",
			wantCode:   2,
			wantStderr: "token: subcommand is required",
		},
		{
			name:       "unknown_subcommand",
			args:       []string{"bogus"},
			wantCode:   2,
			wantStderr: "unknown token subcommand: bogus",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code, err := runToken(context.Background(), tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("exit code: got %d, want %d", code, tt.wantCode)
			}
			if tt.wantStderr == "" {
				if err != nil {
					t.Fatalf("runToken: got error %v, want nil", err)
				}
			} else if err == nil {
				t.Fatalf("expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantStderr) {
				t.Fatalf("error: got %q, want substring %q", err.Error(), tt.wantStderr)
			}
			if tt.wantStdout != "" && !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Fatalf("stdout: got %q, want substring %q", stdout.String(), tt.wantStdout)
			}
		})
	}
}
