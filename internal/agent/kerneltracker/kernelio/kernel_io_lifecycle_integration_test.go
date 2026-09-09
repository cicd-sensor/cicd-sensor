//go:build linux && bpf_integration

package kernelio

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestKernelSampleLoopLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check func(*testing.T, *LinuxKernelIO)
	}{
		{name: "close before start prevents new producers", check: func(t *testing.T, k *LinuxKernelIO) {
			if err := k.Close(); err != nil {
				t.Fatal(err)
			}
			if err := k.StartKernelSampleLoop(t.Context(), discardLifecycleSample); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("start after close: %v", err)
			}
		}},
		{name: "second start cannot orphan the first loop", check: func(t *testing.T, k *LinuxKernelIO) {
			if err := k.StartKernelSampleLoop(t.Context(), discardLifecycleSample); err != nil {
				t.Fatal(err)
			}
			if err := k.StartKernelSampleLoop(t.Context(), discardLifecycleSample); err == nil {
				t.Fatal("second start succeeded")
			}
		}},
		{name: "concurrent start and close join every producer", check: func(t *testing.T, k *LinuxKernelIO) {
			start := make(chan struct{})
			started, closed := make(chan error, 1), make(chan error, 1)
			go func() { <-start; started <- k.StartKernelSampleLoop(t.Context(), discardLifecycleSample) }()
			go func() { <-start; closed <- k.Close() }()
			close(start)
			if err := <-started; err != nil && !errors.Is(err, os.ErrClosed) {
				t.Fatal(err)
			}
			if err := <-closed; err != nil {
				t.Fatal(err)
			}
			if err := k.StartKernelSampleLoop(t.Context(), discardLifecycleSample); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("restart after concurrent close: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, err := NewLinux(nil, testLinuxConfig(t))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := k.Close(); err != nil {
					t.Error(err)
				}
			})
			tc.check(t, k)
		})
	}
}

func discardLifecycleSample(context.Context, KernelSample) error { return nil }
