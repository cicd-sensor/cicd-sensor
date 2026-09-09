package kernelio

import (
	"context"
	"os"
)

const (
	// MaxHTTPPreparationFiles bounds descriptors adopted by one worker request.
	MaxHTTPPreparationFiles = 32
	// HTTPPreparationQueueSize bounds queued batches behind the single attach worker.
	HTTPPreparationQueueSize = 8
)

// HTTPPreparationOptions identifies the lifecycle requesting preparation.
type HTTPPreparationOptions struct {
	Source string
}

// HTTPFilePreparer is implemented by the Linux HTTP worker boundary. It takes
// ownership of every file on entry, including rejection/cancellation. Callers
// must not use or close these descriptors after calling PrepareHTTPFiles.
type HTTPFilePreparer interface {
	PrepareHTTPFiles(context.Context, []*os.File, HTTPPreparationOptions) error
}
