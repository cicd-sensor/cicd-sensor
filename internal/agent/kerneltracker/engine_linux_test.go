//go:build linux

package kerneltracker

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

func TestEnqueueKernelSample(t *testing.T) {
	t.Parallel()

	t.Run("valid sample queues decoded input", func(t *testing.T) {
		t.Parallel()

		engine := newTestKernelTracker(nil, nil, noopKernelIO{}, "")
		sample := encodeForkSample(t, bpfprog.BPFProgramForkSample{
			Kind:                kernelio.SampleKindFork,
			ChildTgid:           101,
			ChildStartBoottime:  201,
			ParentTgid:          301,
			ParentStartBoottime: 401,
			CgroupId:            501,
			TsNs:                601,
		})

		if err := engine.enqueueKernelSample(context.Background(), sample); err != nil {
			t.Fatalf("enqueueKernelSample: %v", err)
		}

		select {
		case input := <-engine.inputCh:
			if _, ok := input.(forkSample); !ok {
				t.Fatalf("queued input = %T, want forkSample", input)
			}
		default:
			t.Fatal("enqueueKernelSample did not queue decoded input")
		}
	})

	t.Run("invalid sample is swallowed", func(t *testing.T) {
		t.Parallel()

		engine := newTestKernelTracker(nil, nil, noopKernelIO{}, "")
		if err := engine.enqueueKernelSample(context.Background(), kernelio.KernelSample{1, 2, 3}); err != nil {
			t.Fatalf("enqueueKernelSample invalid sample error = %v, want nil", err)
		}

		select {
		case input := <-engine.inputCh:
			t.Fatalf("unexpected queued input after invalid sample: %T", input)
		default:
		}
	})

	t.Run("invalid sample logs decode failure", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))
		engine := newTestKernelTracker(logger, nil, noopKernelIO{}, "")
		if err := engine.enqueueKernelSample(context.Background(), kernelio.KernelSample{1, 2, 3}); err != nil {
			t.Fatalf("enqueueKernelSample invalid sample error = %v, want nil", err)
		}

		if !strings.Contains(logs.String(), "kernel_sample_decode_failed") {
			t.Fatalf("decode failure was not logged: %s", logs.String())
		}
	})

	t.Run("canceled context interrupts queue send", func(t *testing.T) {
		t.Parallel()

		engine := newTestKernelTracker(nil, nil, noopKernelIO{}, "")
		engine.inputCh = make(chan engineInput)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		sample := encodeForkSample(t, bpfprog.BPFProgramForkSample{
			Kind: kernelio.SampleKindFork,
		})
		if err := engine.enqueueKernelSample(ctx, sample); !errors.Is(err, context.Canceled) {
			t.Fatalf("enqueueKernelSample canceled error = %v, want context.Canceled", err)
		}
	})
}
