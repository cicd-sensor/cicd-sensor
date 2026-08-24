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
	// hint, process scan, attach, and maps-liveness reclaim). It does not gate BPF
	// load: LoadAndAssign loads and verifies the programs at startup either way.
	// Keep this rollout switch off until the Stage 1b-2 environment gates pass;
	// it is not intended as a long-lived user-facing setting.
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
	// QueueHTTPUprobeReconciliation takes ownership of an active userspace
	// cgroup-ID snapshot and schedules a non-blocking maps-liveness sweep.
	// It is a no-op when HTTP uprobe capture is disabled.
	QueueHTTPUprobeReconciliation(activeCgroupIDs []uint64)
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
