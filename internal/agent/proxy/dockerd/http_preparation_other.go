//go:build !linux

package dockerd

import (
	"context"
	"errors"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
)

func resolveDockerTarget(context.Context, string, string, bool) (httpprepare.Process, error) {
	return httpprepare.Process{}, errors.New("HTTP preparation requires Linux")
}
