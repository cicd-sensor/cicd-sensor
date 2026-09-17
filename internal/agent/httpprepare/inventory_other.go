//go:build !linux

package httpprepare

import (
	"context"
	"errors"
	"os"
)

// OpenFiles is unavailable outside the supported Linux runner platforms.
func OpenFiles(context.Context, string) ([]*os.File, error) {
	return nil, errors.New("HTTP preparation requires Linux")
}
