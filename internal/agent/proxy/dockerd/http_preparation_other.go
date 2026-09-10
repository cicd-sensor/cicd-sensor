//go:build !linux

package dockerd

import (
	"context"
	"errors"
)

func resolveDockerTarget(context.Context, string, string, bool) (string, error) {
	return "", errors.New("HTTP preparation requires Linux")
}
