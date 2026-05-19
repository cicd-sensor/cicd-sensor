package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
)

type managerConnectionConfig struct {
	URL   string
	Token string
}

func resolveManagerTokenSecret(tokenFile string, logger *slog.Logger) (string, error) {
	token, err := managerauth.ResolveToken(os.Getenv("CICD_SENSOR_MANAGER_TOKEN"), tokenFile, logger)
	if err != nil {
		return "", err
	}
	if token != "" && !managerauth.IsValidToken(token) {
		return "", fmt.Errorf("%s", managerauth.ValidTokenDescription())
	}
	return token, nil
}
