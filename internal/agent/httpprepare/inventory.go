// Package httpprepare supplies bounded target files to the existing KernelIO
// worker. It owns neither classification nor HTTP uprobe links.
package httpprepare

import (
	"os"
	"time"
)

const (
	// Budget covers root acquisition, inventory, transfer, queueing and attachment.
	Budget               = 500 * time.Millisecond
	MaxFiles             = 32
	maxDirectories       = 32
	maxDirectoryEntries  = 512
	maxCandidateAttempts = 128
)

// InventoryStats measures work even when enumeration stops at a resource limit.
type InventoryStats struct {
	Directories, Entries, Candidates, Opened, Missing, Failed int
	Truncated                                                 bool
}

// CloseFiles releases files not transferred to the preparation API.
func CloseFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}
