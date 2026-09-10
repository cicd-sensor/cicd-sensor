package kerneltracker

import (
	"context"
	"os"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

// PrepareHTTPFiles forwards directly to KernelIO, bypassing the tracking reactor.
// It adopts the files even on unsupported platforms; no Job/scope state is read.
func (engine *KernelTracker) PrepareHTTPFiles(ctx context.Context, files []*os.File, source string, membership *os.File) error {
	if preparer, ok := engine.kernelIO.(kernelio.HTTPFilePreparer); ok {
		return preparer.PrepareHTTPFiles(ctx, files, source, membership)
	}
	if membership != nil {
		_ = membership.Close()
	}
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
	return kernelio.ErrNotSupported
}
