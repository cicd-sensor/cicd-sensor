//go:build !linux

package httpprepare

import (
	"context"
	"errors"
	"log/slog"
)

func prepareRemote(context.Context, string, string, []string, string) error {
	return errors.New("HTTP preparation requires Linux")
}

// Serve is unavailable outside the supported Linux runner platforms.
func Serve(context.Context, string, FileHandler, *slog.Logger) error {
	return errors.New("HTTP preparation requires Linux")
}
