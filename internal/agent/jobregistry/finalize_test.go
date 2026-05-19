package jobregistry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

var (
	testCtx    = context.Background()
	testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))
)

func newTestJobRegistry() *JobRegistry {
	return &JobRegistry{
		logger:    testLogger.With("component", "job_registry"),
		jobLogger: testLogger,
		jobs:      make(map[jobcontext.JobIdentity]*job.Job),
		starting:  make(map[jobcontext.JobIdentity]chan struct{}),
	}
}

func TestJobRegistry_FinalizeAll_RemovesJobs(t *testing.T) {
	t.Parallel()

	jr := newTestJobRegistry()
	for _, jobID := range []string{"a", "b"} {
		if _, err := jr.ApplyGitHubProjectStart(testCtx, jobcontext.GitLabJobIdentity("gitlab.com", "group/project", jobID), jobcontext.JobMetadata{}, "machine", 0, 0, nil, managerclient.Connection{}, nil, false); err != nil {
			t.Fatalf("start %s: %v", jobID, err)
		}
	}

	jr.FinalizeAll(testCtx, kerneltracker.EndShutdown)

	if len(jr.All()) != 0 {
		t.Fatalf("jobs remaining: got %d, want 0", len(jr.All()))
	}
}

func TestJobRegistry_FinalizeExpiredJobs_RemovesJob(t *testing.T) {
	t.Parallel()

	jr := newTestJobRegistry()
	j, err := jr.ApplyGitHubProjectStart(testCtx, jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"), jobcontext.JobMetadata{}, "machine", 0, 0, nil, managerclient.Connection{}, nil, false)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	j.SetDeadlineAtForTesting(time.Now().Add(-time.Second))

	jr.FinalizeExpiredJobs(testCtx)

	if got := jr.get(j.Identity()); got != nil {
		t.Fatalf("expected expired job to be removed, got %#v", got)
	}
}

func TestJobRegistry_FinalizeAll_ScopeLessJobsAreRemoved(t *testing.T) {
	t.Parallel()

	jr := newTestJobRegistry()
	if _, err := jr.registerJobRuntime(testCtx, jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"), jobcontext.JobMetadata{}, "machine"); err != nil {
		t.Fatalf("register: %v", err)
	}

	jr.FinalizeAll(testCtx, kerneltracker.EndShutdown)

	if len(jr.All()) != 0 {
		t.Fatalf("jobs remaining: got %d, want 0", len(jr.All()))
	}
}

func TestJobRegistry_RequestGitHubHostEnd_FinalizesHostJob(t *testing.T) {
	t.Parallel()

	jr := newTestJobRegistry()
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	if _, err := jr.ApplyGitHubHostStart(testCtx, id, jobcontext.JobMetadata{}, "machine", 0, managerclient.Connection{}, fakeManagerFetcher{}, false); err != nil {
		t.Fatalf("host start: %v", err)
	}

	if err := jr.RequestGitHubHostEnd(testCtx, id, 1); err != nil {
		t.Fatalf("host end: %v", err)
	}
	if got := jr.get(id); got != nil {
		t.Fatalf("expected job to be removed, got %#v", got)
	}
}

func TestJobRegistry_RequestGitHubHostEnd_ProjectOnlyJobReturnsError(t *testing.T) {
	t.Parallel()

	jr := newTestJobRegistry()
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	if _, err := jr.ApplyGitHubProjectStart(testCtx, id, jobcontext.JobMetadata{}, "machine", 0, 0, nil, managerclient.Connection{}, nil, false); err != nil {
		t.Fatalf("project start: %v", err)
	}

	if err := jr.RequestGitHubHostEnd(testCtx, id, 1); !errors.Is(err, ErrHostScopeMissing) {
		t.Fatalf("host end error: got %v, want ErrHostScopeMissing", err)
	}
	if got := jr.get(id); got == nil {
		t.Fatal("project-only job should remain registered")
	}
}

func TestJobRegistry_RequestGitHubHostEnd_MissingJobIsIdempotent(t *testing.T) {
	t.Parallel()

	jr := newTestJobRegistry()
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	if err := jr.RequestGitHubHostEnd(testCtx, id, 1); err != nil {
		t.Fatalf("host end missing job: %v", err)
	}
}

func TestJobRegistry_GetGitHubJobHealth(t *testing.T) {
	t.Parallel()

	jr := newTestJobRegistry()
	hostID := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	if _, err := jr.ApplyGitHubHostStart(testCtx, hostID, jobcontext.JobMetadata{}, "machine", 0, managerclient.Connection{}, fakeManagerFetcher{}, false); err != nil {
		t.Fatalf("host start: %v", err)
	}
	hostHealth, err := jr.GetGitHubJobHealth(testCtx, hostID, 1)
	if err != nil {
		t.Fatalf("job health: %v", err)
	}
	if !hostHealth.HostActive || hostHealth.ProjectActive {
		t.Fatalf("host-only health: got host=%v project=%v, want host=true project=false", hostHealth.HostActive, hostHealth.ProjectActive)
	}
	if got := jr.get(hostID); got == nil {
		t.Fatal("job health should not remove the job")
	}

	projectOnlyID := jobcontext.GitHubJobIdentity("github.com", "acme/example", "124", "build", "1", "runner-2")
	if _, err := jr.ApplyGitHubProjectStart(testCtx, projectOnlyID, jobcontext.JobMetadata{}, "machine", 0, 0, nil, managerclient.Connection{}, nil, false); err != nil {
		t.Fatalf("project start: %v", err)
	}
	projectHealth, err := jr.GetGitHubJobHealth(testCtx, projectOnlyID, 1)
	if err != nil {
		t.Fatalf("project-only job health: %v", err)
	}
	if projectHealth.HostActive || !projectHealth.ProjectActive {
		t.Fatalf("project-only health: got host=%v project=%v, want host=false project=true", projectHealth.HostActive, projectHealth.ProjectActive)
	}

	missingID := jobcontext.GitHubJobIdentity("github.com", "acme/example", "125", "build", "1", "runner-3")
	if _, err := jr.GetGitHubJobHealth(testCtx, missingID, 1); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("missing job health: got %v, want ErrJobNotFound", err)
	}
}

func TestJobRegistry_OnJobEnded_FinalizesAndRemovesJob(t *testing.T) {
	t.Parallel()

	jr := newTestJobRegistry()
	id := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	if _, err := jr.registerJobRuntime(testCtx, id, jobcontext.JobMetadata{}, "machine"); err != nil {
		t.Fatalf("register: %v", err)
	}

	jr.OnJobEnded(id, kerneltracker.EndCgroupRmdir)

	waitForJob(t, "OnJobEnded removes job", func() bool {
		return jr.get(id) == nil
	})
}
