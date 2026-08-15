package kernelio

import (
	"context"
	"errors"
)

var ErrNotSupported = errors.New("not supported")

// Config contains the cgroup v2 root detected by KernelTracker.
type Config struct {
	CgroupV2RootPath string
	// EnableOpenSSLHTTP turns on the OpenSSL uprobe HTTP tap and its attach
	// discovery. Off by default: Stage 1b-1 ships disabled because it has no
	// reclaim yet (attaches accumulate). Kept internal to Config until Stage
	// 1b-2 adds reclaim and a public flag.
	EnableOpenSSLHTTP bool
}

// KernelIO is the BPF program/map/ringbuf I/O boundary. It stays as an
// interface so engine loop tests can run without loading kernel programs.
type KernelIO interface {
	PutCgroupIDInTrackedCgroupsMap(ctx context.Context, cgroupID uint64) error
	DeleteCgroupIDsFromTrackedCgroupsMap(ctx context.Context, cgroupIDs []uint64) error
	PutCgroupBasenameInStagingMap(ctx context.Context, basename string) error
	DeleteCgroupBasenamesFromStagingMap(ctx context.Context, basenames []string) error
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
