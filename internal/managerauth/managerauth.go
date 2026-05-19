package managerauth

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

const minTokenSecretLength = 64

// TokenPrefix is the fixed bearer token prefix used between agent and manager.
const TokenPrefix = "sk_cs_"

// ResolveToken returns the bearer token selected from CLI / env input.
// A flag-supplied file takes precedence over the env value.
func ResolveToken(envValue, filePath string, logger *slog.Logger) (string, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if filePath != "" && envValue != "" {
		logger.Warn("manager_token_both_sources_specified",
			"preferred", "manager-token-file",
			"ignored", "CICD_SENSOR_MANAGER_TOKEN env",
		)
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read manager token file %q: %w", filePath, err)
		}
		return strings.TrimRight(string(data), "\n"), nil
	}
	return envValue, nil
}

// IsValidToken reports whether token has the cicd-sensor prefix and enough entropy.
func IsValidToken(token string) bool {
	secret, ok := strings.CutPrefix(token, TokenPrefix)
	return ok && len(secret) >= minTokenSecretLength
}

func ValidTokenDescription() string {
	return "manager token must start with sk_cs_ and contain at least 64 characters after the prefix"
}
