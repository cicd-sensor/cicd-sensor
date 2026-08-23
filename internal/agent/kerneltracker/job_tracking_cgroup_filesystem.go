package kerneltracker

import (
	"context"
	"sync"
	"time"
)

const cgroupFilesystemScanInterval = time.Minute

// cgroupFilesystemSnapshot is produced outside the KernelTracker engine loop.
// It contains only immutable scan output; ownership decisions stay inside the
// loop when the snapshot is handled as an engine input.
type cgroupFilesystemSnapshot struct {
	ScanStartedAt   time.Time
	CheckedAt       time.Time
	CgroupPathsByID map[uint64]string
	DirectoryCount  int
	StatErrorCount  int
}

func (cgroupFilesystemSnapshot) sealedEngineInput() {}

// startCgroupFilesystemScanner runs filesystem work outside the state-owner loop.
// Scanning /sys/fs/cgroup can block briefly, so the goroutine sends only a
// completed ID/path snapshot back through inputCh for serialized reconciliation.
func (engine *KernelTracker) startCgroupFilesystemScanner(ctx context.Context) func() {
	if engine.cgroupV2RootPath == "" {
		return func() {}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(cgroupFilesystemScanInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				engine.scanAndQueueCgroupFilesystemSnapshot(ctx)
			}
		}
	}()
	return wg.Wait
}

// scanAndQueueCgroupFilesystemSnapshot keeps ScanStartedAt from before the walk. The
// engine loop uses it to ignore cgroups first tracked while this scan was in
// progress, because those cgroups may legitimately be absent from the snapshot.
func (engine *KernelTracker) scanAndQueueCgroupFilesystemSnapshot(ctx context.Context) {
	// Keep the monotonic reading for comparison with cgroup TrackedAt values
	// recorded in this process.
	scanStartedAt := time.Now()
	snapshot, err := scanCgroupFilesystem(engine.cgroupV2RootPath)
	if err != nil {
		engine.logger.WarnContext(ctx, "cgroup_liveness_scan_failed", "error", err)
		return
	}
	snapshot.ScanStartedAt = scanStartedAt
	snapshot.CheckedAt = time.Now().UTC()

	select {
	case engine.inputCh <- snapshot:
	case <-ctx.Done():
	}
}
