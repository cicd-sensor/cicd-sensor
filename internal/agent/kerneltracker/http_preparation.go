package kerneltracker

import (
	"context"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
)

// PrepareHTTP bypasses the tracking reactor; KernelIO queues process metadata.
func (engine *KernelTracker) PrepareHTTP(ctx context.Context, process httpprepare.Process) error {
	return engine.kernelIO.PrepareHTTP(ctx, process)
}
