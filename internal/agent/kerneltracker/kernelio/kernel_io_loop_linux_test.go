//go:build linux

package kernelio

import (
	"context"
	"testing"

	"github.com/cilium/ebpf/ringbuf"
)

func TestStartKernelSampleLoopRequiresInitializedReader(t *testing.T) {
	t.Parallel()

	kernelIO := &LinuxKernelIO{}
	err := kernelIO.StartKernelSampleLoop(context.Background(), func(context.Context, KernelSample) error {
		return nil
	})
	if err == nil {
		t.Fatalf("expected uninitialized reader error")
	}
}

func TestStartKernelSampleLoopRequiresHandler(t *testing.T) {
	t.Parallel()

	kernelIO := &LinuxKernelIO{reader: &ringbuf.Reader{}}
	if err := kernelIO.StartKernelSampleLoop(context.Background(), nil); err == nil {
		t.Fatalf("expected nil handler error")
	}
}

func TestCloseZeroValueKernelIO(t *testing.T) {
	t.Parallel()

	kernelIO := &LinuxKernelIO{}
	if err := kernelIO.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestReadRingbufDropCountRequiresMap(t *testing.T) {
	t.Parallel()

	kernelIO := &LinuxKernelIO{}
	if _, err := kernelIO.readRingbufDropCount(); err == nil {
		t.Fatalf("expected missing ringbuf drop count map error")
	}
}
