package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
)

func TestResolveManagerTokenSecret(t *testing.T) {
	validToken := managerauth.TokenPrefix + strings.Repeat("a", 64)

	t.Run("env token", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", validToken)

		got, err := resolveManagerTokenSecret("", discardLogger())
		if err != nil {
			t.Fatalf("resolveManagerTokenSecret: %v", err)
		}
		if got != validToken {
			t.Fatalf("token: got %q, want env token", got)
		}
	})

	t.Run("file token", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", "")
		tokenPath := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(tokenPath, []byte(validToken+"\n"), 0o600); err != nil {
			t.Fatalf("write token file: %v", err)
		}

		got, err := resolveManagerTokenSecret(tokenPath, discardLogger())
		if err != nil {
			t.Fatalf("resolveManagerTokenSecret: %v", err)
		}
		if got != validToken {
			t.Fatalf("token: got %q, want file token", got)
		}
	})

	t.Run("short token rejected", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", managerauth.TokenPrefix+strings.Repeat("a", 63))

		_, err := resolveManagerTokenSecret("", discardLogger())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "at least 64 characters") {
			t.Fatalf("error: got %q", err.Error())
		}
	})

	t.Run("missing file error", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", "")

		_, err := resolveManagerTokenSecret(filepath.Join(t.TempDir(), "missing-token"), discardLogger())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "read manager token file") {
			t.Fatalf("error: got %q", err.Error())
		}
	})
}

func TestBuildProjectManagerConnection(t *testing.T) {
	validToken := managerauth.TokenPrefix + strings.Repeat("a", 64)

	t.Run("no manager url ignores env token", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", validToken)

		got, err := buildProjectManagerConnection("", "", discardLogger())
		if err != nil {
			t.Fatalf("buildProjectManagerConnection: %v", err)
		}
		if got != (managerConnectionConfig{}) {
			t.Fatalf("manager config: got %#v, want empty", got)
		}
	})

	t.Run("token file without manager url is rejected", func(t *testing.T) {
		_, err := buildProjectManagerConnection("", filepath.Join(t.TempDir(), "missing-token"), discardLogger())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "--manager-token-file requires --manager-url") {
			t.Fatalf("error: got %q", err.Error())
		}
	})

	t.Run("manager url without token returns config for request builder validation", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", "")

		got, err := buildProjectManagerConnection("https://project-manager.example.com", "", discardLogger())
		if err != nil {
			t.Fatalf("buildProjectManagerConnection: %v", err)
		}
		if got.URL != "https://project-manager.example.com" {
			t.Fatalf("manager url: got %q", got.URL)
		}
		if got.Token != "" {
			t.Fatalf("manager token: got %q, want empty", got.Token)
		}
	})

	t.Run("manager url with env token", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", validToken)

		got, err := buildProjectManagerConnection("https://project-manager.example.com", "", discardLogger())
		if err != nil {
			t.Fatalf("buildProjectManagerConnection: %v", err)
		}
		if got.URL != "https://project-manager.example.com" {
			t.Fatalf("manager url: got %q", got.URL)
		}
		if got.Token != validToken {
			t.Fatalf("manager token: got %q, want env token", got.Token)
		}
	})
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
