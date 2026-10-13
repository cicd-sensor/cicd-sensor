package main

import (
	"log/slog"
	"os"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
)

type managerConnectionConfig struct {
	URL                 string
	Token               string
	Auth                string
	IDTokenRequestURL   string
	IDTokenRequestToken string
	IDTokenAudience     string
}

func resolveManagerTokenSecret(tokenFile string, logger *slog.Logger) (string, error) {
	token, err := managerauth.ResolveToken(os.Getenv("CICD_SENSOR_MANAGER_TOKEN"), tokenFile, logger)
	if err != nil {
		return "", err
	}
	return token, nil
}

func normalizeManagerAuth(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "manager-token":
		return managerclient.TokenTypeManagerToken
	case "oidc":
		return "oidc"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}
