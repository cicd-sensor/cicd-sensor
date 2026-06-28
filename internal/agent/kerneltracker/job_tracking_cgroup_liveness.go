package kerneltracker

import (
	"context"
	"sync"
	"time"
)

const cgroupLivenessScanInterval = time.Minute

// cgroupLivenessSnapshot is produced outside the KernelTracker engine loop.
// It contains only immutable scan output; ownership decisions stay inside the
// loop when commandReconcileCgroupLiveness is handled.
type cgroupLivenessSnapshot struct {
	LiveCgroupIDs  map[uint64]struct{}
	DirectoryCount int
	StatErrorCount int
}

// startCgroupLivenessScanner runs filesystem work outside the state-owner loop.
// Scanning /sys/fs/cgroup can block briefly, so the goroutine sends only a
// completed live-ID snapshot back through inputCh for serialized reconciliation.
func (engine *KernelTracker) startCgroupLivenessScanner(ctx context.Context) func() {
	if engine.cgroupV2RootPath == "" {
		return func() {}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(cgroupLivenessScanInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				engine.scanAndQueueCgroupLiveness(ctx)
			}
		}
	}()
	return wg.Wait
}

// scanAndQueueCgroupLiveness keeps ScanStartedAt from before the walk. The
// engine loop uses it to ignore cgroups first tracked while this scan was in
// progress, because those cgroups may legitimately be absent from the snapshot.
func (engine *KernelTracker) scanAndQueueCgroupLiveness(ctx context.Context) {
	scanStartedAt := time.Now().UTC()
	snapshot, err := scanLiveCgroupIDs(engine.cgroupV2RootPath)
	checkedAt := time.Now().UTC()
	if err != nil {
		engine.logger.WarnContext(ctx, "cgroup_liveness_scan_failed", "error", err)
		return
	}

	select {
	case engine.inputCh <- commandReconcileCgroupLiveness{
		ScanStartedAt:  scanStartedAt,
		CheckedAt:      checkedAt,
		LiveCgroupIDs:  snapshot.LiveCgroupIDs,
		StatErrorCount: snapshot.StatErrorCount,
	}:
	case <-ctx.Done():
	}
}
