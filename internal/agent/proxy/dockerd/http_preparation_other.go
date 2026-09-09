//go:build !linux

package dockerd

import (
	"context"
	"errors"
)

func resolveDockerTarget(context.Context, string, string, bool) (string, []string, error) {
	return "", nil, errors.New("HTTP preparation requires Linux")
}
