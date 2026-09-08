//go:build !linux

package dockerd

import (
	"context"
	"errors"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
)

func prepareDockerTarget(context.Context, string, string, bool, *httpprepare.Preparation) error {
	return errors.New("HTTP preparation requires Linux")
}
