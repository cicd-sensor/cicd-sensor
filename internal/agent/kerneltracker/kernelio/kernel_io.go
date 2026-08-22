package kernelio

import (
	"context"
	"errors"
)

var ErrNotSupported = errors.New("not supported")

// Config contains the cgroup v2 root detected by KernelTracker.
type Config struct {
	CgroupV2RootPath string
	// EnableOpenSSLHTTP starts the OpenSSL uprobe attach-discovery worker (connect
	// hint + process scan + attach) — the runtime that makes the tap capture. It does
	// NOT gate BPF load: the uprobe programs are loaded and verified at startup
	// either way (LoadAndAssign loads every program), so this is a kill-switch
	// for a new attach subsystem, not a load-safety gate. Off in Stage 1b-1
	// because attach reclaim is missing (Stage 1b-2): without it, distinct
	// overlay/container libssl inodes accumulate attaches up to the target cap on
	// long-lived agents and silently lose coverage. Temporary: once 1b-2 reclaim
	// lands and its gates pass, the tap defaults on and this flag is removed; it
	// is not a long-lived opt-in/opt-out surface.
	EnableOpenSSLHTTP bool
}

// KernelIO is the BPF program/map/ringbuf I/O boundary. It stays as an
// interface so engine loop tests can run without loading kernel programs.
type KernelIO interface {
	PutCgroupIDInTrackedCgroupsMap(ctx context.Context, cgroupID uint64) error
	DeleteCgroupIDsFromTrackedCgroupsMap(ctx context.Context, cgroupIDs []uint64) error
	PutCgroupBasenameInStagingMap(ctx context.Context, basename string) error
	DeleteCgroupBasenamesFromStagingMap(ctx context.Context, basenames []string) error
	// QueueHTTPUprobeDiscovery schedules a non-blocking process mapping scan
	// after a TCP connect. It is a no-op when HTTP uprobe capture is disabled.
	QueueHTTPUprobeDiscovery(pid int32)
	// ReconcileHTTPUprobeTargets hands the attach-reclaim worker an immutable
	// snapshot of the processes currently in tracked cgroups. It never blocks the
	// caller and is a no-op when HTTP uprobe capture is disabled.
	ReconcileHTTPUprobeTargets(ctx context.Context, snapshot MappedProcessSnapshot)
	StartKernelSampleLoop(ctx context.Context, handle KernelSampleHandler) error
	Close() error
}

// KernelSample is one raw ringbuf sample payload from the BPF program.
// The bytes are valid only during the handler call; retainers must copy them.
type KernelSample []byte

// KernelSampleHandler receives raw samples from the BPF ring buffer.
type KernelSampleHandler func(context.Context, KernelSample) error

const (
	TrackedCgroupsMapName = "tracked_cgroups"
	StagingMapName        = "staging_map"
	StagingKeyLen         = 256
	StagingValueLen       = 16
	StagingMaxEntries     = 1024
)
