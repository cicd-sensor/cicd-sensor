//go:build linux

package kerneltracker

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestKernelTrackerRegisterJobAndBindProcessCgroupToJob(t *testing.T) {
	t.Parallel()

	cgroupRoot := mustCgroupV2Root(t)
	engine := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()

	jobID := jobcontext.JobIdentity{}
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}
	if eventCh == nil {
		t.Fatal("RegisterJob returned nil event channel")
	}

	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run error = %v, want nil", err)
	}
}

func TestKernelTrackerAPIs_ReturnContextErrorWhenCanceledAfterQueue(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "queued-cancel")

	tests := []struct {
		name string
		call func(context.Context, *KernelTracker) error
	}{
		{
			name: "RegisterJob",
			call: func(ctx context.Context, engine *KernelTracker) error {
				_, err := engine.RegisterJob(ctx, jobID)
				return err
			},
		},
		{
			name: "BindProcessCgroupToJob",
			call: func(ctx context.Context, engine *KernelTracker) error {
				return engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid()))
			},
		},
		{
			name: "StageCgroupBasenameForJob",
			call: func(ctx context.Context, engine *KernelTracker) error {
				return engine.StageCgroupBasenameForJob(ctx, "queued-cancel", jobID)
			},
		},
		{
			name: "RemoveJob",
			call: func(ctx context.Context, engine *KernelTracker) error {
				return engine.RemoveJob(ctx, jobID)
			},
		},
		{
			name: "JobForCgroup",
			call: func(ctx context.Context, engine *KernelTracker) error {
				_, err := engine.JobForCgroup(ctx, 42)
				return err
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cgroupRoot := mustCgroupV2Root(t)
			engine := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)

			go func() {
				done <- test.call(ctx, engine)
			}()

			waitForQueuedEngineInput(t, engine)
			cancel()

			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("error = %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("API call did not return after context cancel")
			}
		})
	}
}

func TestKernelTrackerJobForPeerPIDMisses(t *testing.T) {
	t.Parallel()

	engine := newTestKernelTracker(nil, nil, noopKernelIO{}, "/definitely/missing/cgroup-root")
	for _, pid := range []int32{0, -1} {
		result, err := engine.JobForPeerPID(context.Background(), pid)
		if err != nil {
			t.Fatalf("JobForPeerPID(%d) error = %v, want nil", pid, err)
		}
		if result.Found {
			t.Fatalf("JobForPeerPID(%d) found job %v, want miss", pid, result.JobID)
		}
	}

	result, err := engine.JobForPeerPID(context.Background(), int32(os.Getpid()))
	if err != nil {
		t.Fatalf("JobForPeerPID lookup failure error = %v, want nil", err)
	}
	if result.Found {
		t.Fatalf("JobForPeerPID lookup failure found job %v, want miss", result.JobID)
	}
}

func mustCgroupV2Root(t *testing.T) string {
	t.Helper()
	root, err := getCgroupV2Root()
	if err != nil {
		t.Fatalf("getCgroupV2Root: %v", err)
	}
	return root
}

func waitForQueuedEngineInput(t *testing.T, engine *KernelTracker) engineInput {
	t.Helper()

	select {
	case in := <-engine.inputCh:
		return in
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for queued engine input")
		return nil
	}
}
