//go:build !linux

package httpprepare

import (
	"context"
	"errors"
	"log/slog"
)

// Serve is unavailable outside the supported Linux runner platforms.
func Serve(context.Context, string, Handler, *slog.Logger) error {
	return errors.New("HTTP preparation requires Linux")
}
