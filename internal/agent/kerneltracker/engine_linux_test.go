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

	t.Run("only decoded TCP connects queue HTTP uprobe discovery", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name    string
			sample  kernelio.KernelSample
			wantPID int32
			wantHit bool
		}{
			{
				name: "IPv4 TCP connect provides its process pid",
				sample: encodeNetV4Sample(t, bpfprog.BPFProgramNetV4Sample{
					Kind:     kernelio.SampleKindNetworkConnectV4,
					Protocol: ipProtocolTCP,
					Tgid:     101,
				}),
				wantPID: 101,
				wantHit: true,
			},
			{
				name: "IPv6 TCP connect provides its process pid",
				sample: encodeNetV6Sample(t, bpfprog.BPFProgramNetV6Sample{
					Kind:     kernelio.SampleKindNetworkConnectV6,
					Protocol: ipProtocolTCP,
					Tgid:     202,
				}),
				wantPID: 202,
				wantHit: true,
			},
			{
				name: "UDP connect does not trigger an HTTP uprobe scan",
				sample: encodeNetV4Sample(t, bpfprog.BPFProgramNetV4Sample{
					Kind:     kernelio.SampleKindNetworkConnectV4,
					Protocol: 17,
					Tgid:     303,
				}),
			},
			{
				name: "non-network sample does not trigger an HTTP uprobe scan",
				sample: encodeForkSample(t, bpfprog.BPFProgramForkSample{
					Kind: kernelio.SampleKindFork,
				}),
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				kernelIO := &recordingKernelIO{}
				engine := newTestKernelTracker(nil, nil, kernelIO, "")
				if err := engine.enqueueKernelSample(t.Context(), test.sample); err != nil {
					t.Fatalf("enqueueKernelSample: %v", err)
				}

				if !test.wantHit {
					if len(kernelIO.httpUprobeDiscoveryPIDs) != 0 {
						t.Fatalf("HTTP uprobe discovery PIDs = %v, want none", kernelIO.httpUprobeDiscoveryPIDs)
					}
					return
				}
				if len(kernelIO.httpUprobeDiscoveryPIDs) != 1 || kernelIO.httpUprobeDiscoveryPIDs[0] != test.wantPID {
					t.Fatalf("HTTP uprobe discovery PIDs = %v, want [%d]", kernelIO.httpUprobeDiscoveryPIDs, test.wantPID)
				}
			})
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
