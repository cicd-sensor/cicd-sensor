package managerauth

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveToken(t *testing.T) {
	tests := []struct {
		name       string
		envValue   string
		fileValue  *string
		filePath   string
		want       string
		wantWarn   bool
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:     "env only",
			envValue: "env-token",
			want:     "env-token",
		},
		{
			name:      "file only trims trailing newlines",
			fileValue: ptrString("file-token\n\n"),
			want:      "file-token",
		},
		{
			name:      "file without trailing newline",
			fileValue: ptrString("file-token"),
			want:      "file-token",
		},
		{
			name:      "file with newline only becomes empty",
			fileValue: ptrString("\n\n"),
			want:      "",
		},
		{
			name:      "empty file becomes empty",
			fileValue: ptrString(""),
			want:      "",
		},
		{
			name:      "file beats env and warns",
			envValue:  "env-token",
			fileValue: ptrString("file-token\n"),
			want:      "file-token",
			wantWarn:  true,
		},
		{
			name: "no token sources",
			want: "",
		},
		{
			name:       "missing file returns error",
			filePath:   filepath.Join("missing", "token"),
			wantErr:    true,
			wantErrMsg: "read manager token file",
		},
		{
			name:       "missing file beats env and returns error",
			envValue:   "env-token",
			filePath:   filepath.Join("missing", "token"),
			wantErr:    true,
			wantErrMsg: "read manager token file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.filePath
			if tt.fileValue != nil {
				filePath = filepath.Join(t.TempDir(), "token")
				if err := os.WriteFile(filePath, []byte(*tt.fileValue), 0o600); err != nil {
					t.Fatalf("write token file: %v", err)
				}
			}

			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			got, err := ResolveToken(tt.envValue, filePath, logger)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.wantErrMsg != "" && !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Fatalf("error: got %q, want containing %q", err, tt.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveToken: %v", err)
			}
			if got != tt.want {
				t.Fatalf("token: got %q, want %q", got, tt.want)
			}
			hasWarn := strings.Contains(logs.String(), "manager_token_both_sources_specified")
			if hasWarn != tt.wantWarn {
				t.Fatalf("warning emitted: got %v, want %v; logs=%s", hasWarn, tt.wantWarn, logs.String())
			}
			if strings.Contains(logs.String(), "env-token") || strings.Contains(logs.String(), "file-token") {
				t.Fatalf("logs should not contain token material: %s", logs.String())
			}
		})
	}
}

func TestResolveToken_NilLogger(t *testing.T) {
	got, err := ResolveToken("env-token", "", nil)
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	if got != "env-token" {
		t.Fatalf("token: got %q, want %q", got, "env-token")
	}
}

func TestIsValidToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{name: "empty"},
		{name: "missing prefix", token: strings.Repeat("a", 64)},
		{name: "too short", token: TokenPrefix + strings.Repeat("a", 63)},
		{name: "minimum length", token: TokenPrefix + strings.Repeat("a", 64), want: true},
		{name: "longer", token: TokenPrefix + strings.Repeat("a", 80), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidToken(tt.token)
			if got != tt.want {
				t.Fatalf("IsValidToken(%q): got %v, want %v", tt.token, got, tt.want)
			}
		})
	}
}

func TestTokenPrefix(t *testing.T) {
	const want = "sk_cs_"
	if TokenPrefix != want {
		t.Fatalf("TokenPrefix: got %q, want %q", TokenPrefix, want)
	}
}

func ptrString(s string) *string {
	return &s
}
