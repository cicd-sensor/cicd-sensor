// Package httpprepare supplies bounded target files to the existing KernelIO
// worker. It owns neither classification nor HTTP uprobe links.
package httpprepare

import (
	"os"
	"time"
)

const (
	// Budget bounds caller waiting, including root acquisition through attachment.
	Budget = 500 * time.Millisecond
	// MaxFiles bounds target files opened by the worker for one process.
	MaxFiles = 32
)

// CloseFiles releases the inventory after the worker finishes preparation.
func CloseFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}
