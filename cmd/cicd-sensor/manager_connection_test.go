package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveManagerTokenSecret(t *testing.T) {
	validToken := "custom-manager-token"

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
	validToken := "custom-manager-token"

	t.Run("no manager url ignores env token", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", validToken)

		got, err := buildProjectManagerConnection("", "", "", "", discardLogger())
		if err != nil {
			t.Fatalf("buildProjectManagerConnection: %v", err)
		}
		if got != (managerConnectionConfig{}) {
			t.Fatalf("manager config: got %#v, want empty", got)
		}
	})

	t.Run("token file without manager url is rejected", func(t *testing.T) {
		_, err := buildProjectManagerConnection("", filepath.Join(t.TempDir(), "missing-token"), "", "", discardLogger())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "--manager-token-file requires --manager-url") {
			t.Fatalf("error: got %q", err.Error())
		}
	})

	t.Run("manager url without token returns config for request builder validation", func(t *testing.T) {
		t.Setenv("CICD_SENSOR_MANAGER_TOKEN", "")

		got, err := buildProjectManagerConnection("https://project-manager.example.com", "", "", "", discardLogger())
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

		got, err := buildProjectManagerConnection("https://project-manager.example.com", "", "", "", discardLogger())
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

	t.Run("oidc forwards actions request env", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://vstoken.actions.githubusercontent.com/token")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-secret")

		got, err := buildProjectManagerConnection("https://manager.example.com", "", "oidc", "", discardLogger())
		if err != nil {
			t.Fatalf("buildProjectManagerConnection: %v", err)
		}
		if got.Auth != "oidc" {
			t.Fatalf("auth: got %q", got.Auth)
		}
		if got.IDTokenRequestURL != "https://vstoken.actions.githubusercontent.com/token" {
			t.Fatalf("request url: got %q", got.IDTokenRequestURL)
		}
		if got.IDTokenRequestToken != "request-secret" {
			t.Fatalf("request token: got %q", got.IDTokenRequestToken)
		}
		if got.Token != "" {
			t.Fatalf("manager token must be empty for oidc")
		}
	})

	t.Run("oidc requires request url env", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-secret")
		_, err := buildProjectManagerConnection("https://manager.example.com", "", "oidc", "", discardLogger())
		if err == nil || !strings.Contains(err.Error(), "ACTIONS_ID_TOKEN_REQUEST_URL") {
			t.Fatalf("error: got %v", err)
		}
	})
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
