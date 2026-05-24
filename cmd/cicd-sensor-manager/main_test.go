package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/manager"
	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
)

func TestValidateManagerStartupOptions(t *testing.T) {
	validToken := managerauth.TokenPrefix + strings.Repeat("a", 64)
	tests := []struct {
		name    string
		opts    managerStartupOptions
		wantErr string
	}{
		{
			name: "valid options",
			opts: managerStartupOptions{
				ConfigFile: "manager.yaml",
				Tokens:     []string{validToken},
			},
		},
		{
			name: "missing token",
			opts: managerStartupOptions{
				ConfigFile: "manager.yaml",
			},
			wantErr: "manager token is required",
		},
		{
			name: "missing config",
			opts: managerStartupOptions{
				Tokens: []string{validToken},
			},
			wantErr: "--config-file or CICD_SENSOR_MANAGER_CONFIG_FILE",
		},
		{
			name:    "missing token and config reports token first",
			wantErr: "manager token is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateManagerStartupOptions(tt.opts)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateManagerStartupOptions: got error %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateManagerStartupOptions error: got %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestTokenFileFlags(t *testing.T) {
	var flags tokenFileFlags
	if err := flags.Set("/run/secrets/old-token"); err != nil {
		t.Fatalf("first Set: %v", err)
	}
	if err := flags.Set("/run/secrets/new-token"); err != nil {
		t.Fatalf("second Set: %v", err)
	}
	assertTokens(t, []string(flags), []string{"/run/secrets/old-token", "/run/secrets/new-token"})
	if got := flags.String(); got != "/run/secrets/old-token,/run/secrets/new-token" {
		t.Fatalf("String: got %q", got)
	}
}

func TestResolveManagerTokenSecrets(t *testing.T) {
	validEnvToken := managerauth.TokenPrefix + strings.Repeat("e", 64)
	validEnvToken2 := managerauth.TokenPrefix + strings.Repeat("g", 64)
	validFileToken := managerauth.TokenPrefix + strings.Repeat("f", 64)
	validFileToken2 := managerauth.TokenPrefix + strings.Repeat("h", 64)

	t.Run("env token", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", validEnvToken)
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN_2", "")

		got, err := resolveManagerTokenSecrets(nil, nil)
		if err != nil {
			t.Fatalf("resolveManagerTokenSecrets: got error %v, want nil", err)
		}
		assertTokens(t, got, []string{validEnvToken})
	})

	t.Run("two env tokens", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", validEnvToken)
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN_2", validEnvToken2)

		got, err := resolveManagerTokenSecrets(nil, nil)
		if err != nil {
			t.Fatalf("resolveManagerTokenSecrets: got error %v, want nil", err)
		}
		assertTokens(t, got, []string{validEnvToken, validEnvToken2})
	})

	t.Run("token file trims trailing newline", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", "")
		path := writeTokenFile(t, validFileToken+"\n")

		got, err := resolveManagerTokenSecrets([]string{path}, nil)
		if err != nil {
			t.Fatalf("resolveManagerTokenSecrets: got error %v, want nil", err)
		}
		assertTokens(t, got, []string{validFileToken})
	})

	t.Run("two token files", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", "")
		first := writeTokenFile(t, validFileToken+"\n")
		second := writeTokenFile(t, validFileToken2+"\n")

		got, err := resolveManagerTokenSecrets([]string{first, second}, nil)
		if err != nil {
			t.Fatalf("resolveManagerTokenSecrets: got error %v, want nil", err)
		}
		assertTokens(t, got, []string{validFileToken, validFileToken2})
	})

	t.Run("file source ignores env and warns", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", validEnvToken)
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN_2", validEnvToken2)
		path := writeTokenFile(t, validFileToken+"\n")
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))

		got, err := resolveManagerTokenSecrets([]string{path}, logger)
		if err != nil {
			t.Fatalf("resolveManagerTokenSecrets: got error %v, want nil", err)
		}
		assertTokens(t, got, []string{validFileToken})
		if !strings.Contains(logs.String(), "manager_token_both_sources_specified") {
			t.Fatalf("warning missing: %s", logs.String())
		}
		if strings.Contains(logs.String(), validEnvToken) || strings.Contains(logs.String(), validFileToken) {
			t.Fatalf("logs should not contain token material: %s", logs.String())
		}
	})

	t.Run("three token files returns error", func(t *testing.T) {
		paths := []string{
			writeTokenFile(t, validFileToken),
			writeTokenFile(t, validFileToken2),
			writeTokenFile(t, validFileToken),
		}
		_, err := resolveManagerTokenSecrets(paths, nil)
		if err == nil || !strings.Contains(err.Error(), "at most twice") {
			t.Fatalf("resolveManagerTokenSecrets error: got %v, want max token files error", err)
		}
	})

	t.Run("duplicate tokens are accepted", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", validEnvToken)
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN_2", validEnvToken)
		got, err := resolveManagerTokenSecrets(nil, nil)
		if err != nil {
			t.Fatalf("resolveManagerTokenSecrets: got error %v, want nil", err)
		}
		assertTokens(t, got, []string{validEnvToken, validEnvToken})
	})

	t.Run("invalid secondary token returns error", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", validEnvToken)
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN_2", managerauth.TokenPrefix+strings.Repeat("s", 63))
		_, err := resolveManagerTokenSecrets(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "at least 64 characters") {
			t.Fatalf("resolveManagerTokenSecrets error: got %v, want token length error", err)
		}
	})

	t.Run("missing token file returns error", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", "")
		_, err := resolveManagerTokenSecrets([]string{filepath.Join(t.TempDir(), "missing-token")}, nil)
		if err == nil || !strings.Contains(err.Error(), "open manager token file") {
			t.Fatalf("resolveManagerTokenSecrets error: got %v, want file open error", err)
		}
	})

	t.Run("missing sources returns empty token list", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", "")
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN_2", "")
		got, err := resolveManagerTokenSecrets(nil, nil)
		if err != nil {
			t.Fatalf("resolveManagerTokenSecrets: got error %v, want nil", err)
		}
		assertTokens(t, got, nil)
	})
}

func TestResolveFilePathFromFlagOrEnv(t *testing.T) {
	const envName = "CICD_SENSOR_MANAGER_CONFIG_FILE"
	const logKey = "manager_config_file"
	const warnMsg = "manager_config_file_both_sources_specified"

	t.Run("flag only", func(t *testing.T) {
		t.Setenv(envName, "")
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))

		got := resolveFilePathFromFlagOrEnv("/flag/path", envName, logKey, logger)
		if got != "/flag/path" {
			t.Fatalf("got %q, want /flag/path", got)
		}
		if strings.Contains(logs.String(), warnMsg) {
			t.Fatalf("flag-only path should not warn: %s", logs.String())
		}
	})

	t.Run("env only", func(t *testing.T) {
		t.Setenv(envName, "/env/path")
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))

		got := resolveFilePathFromFlagOrEnv("", envName, logKey, logger)
		if got != "/env/path" {
			t.Fatalf("got %q, want /env/path", got)
		}
		if strings.Contains(logs.String(), warnMsg) {
			t.Fatalf("env-only path should not warn: %s", logs.String())
		}
	})

	t.Run("both set: flag wins and warns", func(t *testing.T) {
		t.Setenv(envName, "/env/path")
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))

		got := resolveFilePathFromFlagOrEnv("/flag/path", envName, logKey, logger)
		if got != "/flag/path" {
			t.Fatalf("got %q, want /flag/path", got)
		}
		if !strings.Contains(logs.String(), warnMsg) {
			t.Fatalf("expected warning %q in logs: %s", warnMsg, logs.String())
		}
		if !strings.Contains(logs.String(), envName) {
			t.Fatalf("warning should name the env var: %s", logs.String())
		}
	})

	t.Run("neither set", func(t *testing.T) {
		t.Setenv(envName, "")
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))

		got := resolveFilePathFromFlagOrEnv("", envName, logKey, logger)
		if got != "" {
			t.Fatalf("got %q, want empty", got)
		}
		if strings.Contains(logs.String(), warnMsg) {
			t.Fatalf("no-source path should not warn: %s", logs.String())
		}
	})

	t.Run("nil logger does not panic when both set", func(t *testing.T) {
		t.Setenv(envName, "/env/path")
		got := resolveFilePathFromFlagOrEnv("/flag/path", envName, logKey, nil)
		if got != "/flag/path" {
			t.Fatalf("got %q, want /flag/path", got)
		}
	})
}

func TestBuildServedConfig(t *testing.T) {
	startup := manager.StartupConfig{
		Revision:                "sha256:config",
		DefaultMaxAlertsPerRule: 7,
	}
	settings := &managerv1.OutputSettings{
		DetectionLog: &managerv1.OutputSetting{
			Enabled:              true,
			FlushThresholdBytes:  1,
			FlushIntervalSeconds: 1,
		},
		SummaryLog: &managerv1.OutputSetting{
			Enabled:              true,
			FlushThresholdBytes:  1,
			FlushIntervalSeconds: 1,
		},
	}

	served := buildServedConfig(startup, settings)

	if served.ConfigRevision != "sha256:config" {
		t.Fatalf("ConfigRevision: got %q, want sha256:config", served.ConfigRevision)
	}
	if served.DefaultMaxAlertsPerRule != 7 {
		t.Fatalf("DefaultMaxAlertsPerRule: got %d, want 7", served.DefaultMaxAlertsPerRule)
	}
	if !served.OutputSettings.GetDetectionLog().GetEnabled() {
		t.Fatalf("detection settings: got false, want true")
	}
	if served.OutputSettings.GetRuntimeEventLog().GetEnabled() {
		t.Fatalf("runtime event settings: got true, want false")
	}
	if !served.OutputSettings.GetSummaryLog().GetEnabled() {
		t.Fatalf("summary settings: got false, want true")
	}
}

func writeTokenFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manager-token")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

func assertTokens(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("tokens: got %d values, want %d (%q)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tokens[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}
