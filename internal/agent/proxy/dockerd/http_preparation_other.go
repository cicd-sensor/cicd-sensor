//go:build !linux

package dockerd

import (
	"context"
	"errors"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
)

func prepareDockerExec(context.Context, string, string, *httpprepare.Preparation) error {
	return errors.New("HTTP preparation requires Linux")
}
