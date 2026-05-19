//go:build linux

package jobregistry

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// startPeerPIDAuthRegistry boots a JobRegistry + KernelTracker pair and tears
// down both at sub-test exit. Each peer-PID auth case needs a fresh
// registry because the KernelTracker binds the test process's cgroup 1:1 with
// the first Job and rejects subsequent ApplyGitHubHostStart calls in the same
// engine instance.
func startPeerPIDAuthRegistry(t *testing.T) (*JobRegistry, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(testCtx)

	jr := New(testLogger)
	kernelTracker, err := kerneltracker.New(testLogger, jr)
	if err != nil {
		t.Skipf("kernel tracker unavailable: %v", err)
	}
	jr.BindKernelTracker(kernelTracker)

	engineDone := make(chan error, 1)
	go func() { engineDone <- kernelTracker.Run(ctx) }()
	t.Cleanup(func() {
		jr.FinalizeAll(context.Background(), kerneltracker.EndShutdown)
		cancel()
		<-engineDone
	})
	return jr, ctx
}

// TestJobRegistry_PeerPIDAuthorization (12d-3d) verifies the peer PID gate
// on /v1/project/start and /v1/project/result. Host-linked and hosted-only
// Jobs both require the caller to live in one of the Job's tracked cgroups.
func TestJobRegistry_PeerPIDAuthorization(t *testing.T) {
	meta := jobcontext.JobMetadata{}
	selfPID := int32(os.Getpid())

	t.Run("host_linked_same_cgroup_peer_authorizes", func(t *testing.T) {
		jr, ctx := startPeerPIDAuthRegistry(t)
		id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "r1")
		if _, err := jr.ApplyGitHubHostStart(ctx, id, meta, "machine", selfPID, managerclient.Connection{}, staticManagerFetcher{}, false); err != nil {
			t.Fatalf("ApplyGitHubHostStart: %v", err)
		}
		if _, err := jr.ApplyGitHubProjectStart(ctx, id, meta, "machine", selfPID, 0, nil, managerclient.Connection{}, nil, false); err != nil {
			t.Fatalf("ApplyGitHubProjectStart same-cgroup peer: %v", err)
		}
		if _, err := jr.RequestGitHubProjectResult(ctx, id, selfPID); err != nil {
			t.Fatalf("RequestGitHubProjectResult same-cgroup peer: %v", err)
		}
	})

	t.Run("host_linked_foreign_cgroup_peer_rejected", func(t *testing.T) {
		jr, ctx := startPeerPIDAuthRegistry(t)
		id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "2", "build", "1", "r1")
		if _, err := jr.ApplyGitHubHostStart(ctx, id, meta, "machine", selfPID, managerclient.Connection{}, staticManagerFetcher{}, false); err != nil {
			t.Fatalf("ApplyGitHubHostStart: %v", err)
		}
		// PID 1 lives in a different cgroup than the test process.
		_, err := jr.ApplyGitHubProjectStart(ctx, id, meta, "machine", 1, 0, nil, managerclient.Connection{}, nil, false)
		if !errors.Is(err, ErrPeerNotInJob) {
			t.Fatalf("ApplyGitHubProjectStart foreign peer: got %v, want ErrPeerNotInJob", err)
		}
		_, err = jr.RequestGitHubProjectResult(ctx, id, 1)
		if !errors.Is(err, ErrPeerNotInJob) {
			t.Fatalf("RequestGitHubProjectResult foreign peer: got %v, want ErrPeerNotInJob", err)
		}
	})

	t.Run("hosted_only_result_uses_project_start_cgroup_gate", func(t *testing.T) {
		jr, ctx := startPeerPIDAuthRegistry(t)
		id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "3", "build", "1", "r1")
		// No ApplyGitHubHostStart: project_start creates a hosted-only Job.
		if _, err := jr.ApplyGitHubProjectStart(ctx, id, meta, "machine", selfPID, 0, nil, managerclient.Connection{}, nil, false); err != nil {
			t.Fatalf("ApplyGitHubProjectStart hosted: %v", err)
		}
		if _, err := jr.RequestGitHubProjectResult(ctx, id, selfPID); err != nil {
			t.Fatalf("RequestGitHubProjectResult hosted same-cgroup peer: %v", err)
		}
		_, err := jr.RequestGitHubProjectResult(ctx, id, 1)
		if !errors.Is(err, ErrPeerNotInJob) {
			t.Fatalf("RequestGitHubProjectResult hosted foreign peer: got %v, want ErrPeerNotInJob", err)
		}
	})
}
