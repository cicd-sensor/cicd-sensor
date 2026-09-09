// Package httpprepare supplies bounded target files to the existing KernelIO
// worker. It owns neither classification nor HTTP uprobe links.
package httpprepare

import (
	"os"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

const (
	// MaxConcurrent bounds retained producers/connections, not parallel attach workers.
	// This is a resource budget, not a measured optimal concurrency.
	MaxConcurrent = 8
	// Budget bounds caller waiting, including root acquisition through attachment.
	Budget = 500 * time.Millisecond
	// MaxFiles is the worker's per-request descriptor limit.
	MaxFiles = kernelio.MaxHTTPPreparationFiles
)

// Inventory work limits bound directory enumeration independently of returned FDs.
const (
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
