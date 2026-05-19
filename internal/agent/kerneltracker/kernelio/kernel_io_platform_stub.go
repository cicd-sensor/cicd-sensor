//go:build !linux

package kernelio

import (
	"context"
	"log/slog"
)

var _ = configureBPFProgramSpec

func New(logger *slog.Logger, config Config) (KernelIO, error) {
	_ = logger
	_ = config
	return &StubKernelIO{}, nil
}

type StubKernelIO struct{}

func (kernelIO *StubKernelIO) PutCgroupIDInTrackedCgroupsMap(ctx context.Context, cgroupID uint64) error {
	_ = ctx
	_ = cgroupID
	return ErrNotSupported
}

func (kernelIO *StubKernelIO) DeleteCgroupIDsFromTrackedCgroupsMap(ctx context.Context, cgroupIDs []uint64) error {
	_ = ctx
	_ = cgroupIDs
	return ErrNotSupported
}

func (kernelIO *StubKernelIO) PutCgroupBasenameInStagingMap(ctx context.Context, basename string) error {
	_ = ctx
	_ = basename
	return ErrNotSupported
}

func (kernelIO *StubKernelIO) DeleteCgroupBasenamesFromStagingMap(ctx context.Context, basenames []string) error {
	_ = ctx
	_ = basenames
	return ErrNotSupported
}

func (kernelIO *StubKernelIO) StartKernelSampleLoop(ctx context.Context, handle KernelSampleHandler) error {
	_ = ctx
	_ = handle
	return ErrNotSupported
}

func (kernelIO *StubKernelIO) Close() error {
	return nil
}
