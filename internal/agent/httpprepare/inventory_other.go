//go:build !linux

package httpprepare

import (
	"context"
	"errors"
	"os"
)

// OpenFiles is unavailable outside the supported Linux runner platforms.
func OpenFiles(context.Context, string, []string) ([]*os.File, InventoryStats, error) {
	return nil, InventoryStats{}, errors.New("HTTP preparation requires Linux")
}
