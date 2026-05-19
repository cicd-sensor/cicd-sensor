package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
)

// tokenSecretBytes is the raw entropy size. 32 bytes hex-encodes to a
// 64-character, 256-bit manager token secret.
const tokenSecretBytes = 32

func runTokenGenerate(_ context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("token generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: cicd-sensorctl token generate")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 2, err
	}
	if fs.NArg() != 0 {
		return 2, newUsageError(2, "token generate: unexpected positional arguments")
	}

	secret, err := generateTokenSecret()
	if err != nil {
		return 1, fmt.Errorf("token generate: %w", err)
	}

	fmt.Fprintln(stdout, managerauth.TokenPrefix+secret)
	return 0, nil
}

// generateTokenSecret returns a lowercase hex secret with 256 bits of
// entropy. The returned string has no prefix; callers prepend
// managerauth.TokenPrefix when emitting a manager bearer token.
func generateTokenSecret() (string, error) {
	buf := make([]byte, tokenSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
