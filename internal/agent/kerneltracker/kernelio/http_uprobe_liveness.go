package kernelio

import "time"

// MappedProcessSnapshot is the immutable reclaim input: the PIDs currently in
// tracked cgroups. It carries PIDs, not identities — deriving identities stays
// in the discovery worker.
type MappedProcessSnapshot struct {
	// ScanStartedAt is taken before any filesystem work; a target observed at
	// or after it is not reclaimed by this snapshot.
	ScanStartedAt time.Time
	// Complete is false if a live process could have been missed; the worker
	// then still attaches but changes no reclaim state.
	Complete bool
	// PIDs are the processes currently in tracked cgroups.
	PIDs []int32

	// Done, when non-nil, is closed by the worker after this snapshot has been
	// reconciled. Tests use it to sequence snapshots deterministically; the
	// production scanner leaves it nil.
	Done chan<- struct{}

	// Counters for the reconcile summary log.
	ScannedCgroups int
	PIDsGone       int // cgroup/proc vanished mid-scan: normal race, does not taint Complete
	ReadErrors     int // errors that could hide a live process: taint Complete
}

// NewMappedProcessSnapshot builds an immutable snapshot. Exposed so
// KernelTracker can construct it without reaching into the struct layout.
func NewMappedProcessSnapshot(scanStartedAt time.Time, complete bool, pids []int32, scannedCgroups, pidsGone, readErrors int) MappedProcessSnapshot {
	return MappedProcessSnapshot{
		ScanStartedAt:  scanStartedAt,
		Complete:       complete,
		PIDs:           pids,
		ScannedCgroups: scannedCgroups,
		PIDsGone:       pidsGone,
		ReadErrors:     readErrors,
	}
}
