// Package httpprepare supplies bounded target files to the existing KernelIO
// worker. It owns neither classification nor HTTP uprobe links.
package httpprepare

import (
	"os"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

const (
	// Budget covers root acquisition, inventory, transfer, queueing and attachment.
	// MaxConcurrent bounds retained producers/connections, not parallel attach workers.
	// Eight admits a small burst while limiting each stage to 8 * 32 target FDs.
	// This is a resource budget, not a measured optimal concurrency.
	MaxConcurrent        = 8
	Budget               = 500 * time.Millisecond
	MaxFiles             = kernelio.MaxHTTPPreparationFiles
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
