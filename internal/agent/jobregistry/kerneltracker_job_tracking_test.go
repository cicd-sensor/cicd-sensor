package jobregistry

import (
	"errors"
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestJobRegistry_FindJobForPeerPID_NoKernelTracker(t *testing.T) {
	t.Parallel()

	jr := newTestJobRegistry()

	_, found, err := jr.FindJobForPeerPID(testCtx, 123)
	if err == nil || !strings.Contains(err.Error(), "kernel tracking disabled") {
		t.Fatalf("FindJobForPeerPID error: got %v, want kernel tracking disabled", err)
	}
	if found {
		t.Fatal("found: got true, want false")
	}
}

func TestJobRegistry_StageCgroupBasenameForJob_NoKernelTracker(t *testing.T) {
	t.Parallel()

	jr := newTestJobRegistry()
	id := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")

	err := jr.StageCgroupBasenameForJob(testCtx, "docker-cafef00d.scope", id)
	if err == nil || !strings.Contains(err.Error(), "kernel tracking disabled") {
		t.Fatalf("StageCgroupBasenameForJob error: got %v, want kernel tracking disabled", err)
	}
}

func TestJobRegistry_StageCgroupBasenameForJob_MissingJob(t *testing.T) {
	t.Parallel()

	jr := newTestJobRegistry()
	jr.kernelTracker = fakeUnavailableKernelTracker()
	id := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")

	if err := jr.StageCgroupBasenameForJob(testCtx, "docker-cafef00d.scope", id); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("StageCgroupBasenameForJob missing job: got %v, want %v", err, ErrJobNotFound)
	}
}

func fakeUnavailableKernelTracker() *kerneltracker.KernelTracker {
	return &kerneltracker.KernelTracker{}
}
