package kernelio

import (
	"context"
	"os"
)

// HTTPPreparationOptions describes a bounded preparation request. Pin is reserved
// for the machine's fixed inventory; runtime/context targets use a short grace.
type HTTPPreparationOptions struct {
	Source string
	Pin    bool
}

// HTTPPreparationResult counts target files, not individual uprobe links.
type HTTPPreparationResult struct{ Prepared, Skipped, Failed int }

// HTTPFilePreparer is implemented by the Linux HTTP worker boundary. It takes
// ownership of every file on entry, including rejection/cancellation. Callers
// must not use or close these descriptors after calling PrepareHTTPFiles.
type HTTPFilePreparer interface {
	PrepareHTTPFiles(context.Context, []*os.File, HTTPPreparationOptions) (HTTPPreparationResult, error)
}
