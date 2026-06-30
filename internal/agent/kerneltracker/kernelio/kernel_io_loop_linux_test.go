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

func TestCloseNilReceiver(t *testing.T) {
	t.Parallel()

	var kernelIO *LinuxKernelIO
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

func TestRingbufDropWarnState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		totals []uint64
		want   []ringbufDropWarnDecision
	}{
		{
			name:   "unchanged zero never warns",
			totals: []uint64{0, 0},
			want:   []ringbufDropWarnDecision{{}, {}},
		},
		{
			name:   "first observed drop warns",
			totals: []uint64{1},
			want:   []ringbufDropWarnDecision{{dropped: 1, warn: true}},
		},
		{
			name:   "same bucket increase stays quiet",
			totals: []uint64{2, 3},
			want:   []ringbufDropWarnDecision{{dropped: 2, warn: true}, {}},
		},
		{
			name:   "crossing power of two warns",
			totals: []uint64{2, 3, 4},
			want:   []ringbufDropWarnDecision{{dropped: 2, warn: true}, {}, {dropped: 2, warn: true}},
		},
		{
			name:   "large one-poll jump waits for the next threshold",
			totals: []uint64{0, 100, 100, 127, 128},
			want: []ringbufDropWarnDecision{
				{},
				{dropped: 100, warn: true},
				{},
				{},
				{dropped: 28, warn: true},
			},
		},
		{
			name:   "large jump warns once with full delta",
			totals: []uint64{1, 10},
			want:   []ringbufDropWarnDecision{{dropped: 1, warn: true}, {dropped: 9, warn: true}},
		},
		{
			name:   "counter rollback stays quiet until previous warning total is exceeded",
			totals: []uint64{8, 4, 8, 16},
			want:   []ringbufDropWarnDecision{{dropped: 8, warn: true}, {}, {}, {dropped: 8, warn: true}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var state ringbufDropWarnState
			for i, total := range tc.totals {
				dropped, warn := state.shouldWarn(total)
				if warn != tc.want[i].warn || dropped != tc.want[i].dropped {
					t.Fatalf("step %d total %d: got dropped=%d warn=%v, want dropped=%d warn=%v",
						i, total, dropped, warn, tc.want[i].dropped, tc.want[i].warn)
				}
			}
		})
	}
}

type ringbufDropWarnDecision struct {
	dropped uint64
	warn    bool
}
