package jobregistry_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestJobRegistry_StageCgroupBasenameForJob_BlockedDuringHostStartInflight(t *testing.T) {
	fetcher := &slowFetcher{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	jr := jobregistry.New(testLogger)

	kernelTracker, err := kerneltracker.New(testLogger, nil)
	if err != nil {
		t.Skipf("kernel tracker unavailable: %v", err)
	}
	jr.BindKernelTracker(kernelTracker)
	engineCtx, engineCancel := context.WithCancel(context.Background())
	engineDone := make(chan error, 1)
	go func() { engineDone <- kernelTracker.Run(engineCtx) }()
	defer func() {
		engineCancel()
		<-engineDone
	}()

	id := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "999")
	meta := jobcontext.JobMetadata{}

	startDone := make(chan error, 1)
	go func() {
		_, err := jr.ApplyGitLabHostStart(testCtx, id, meta, "machine", managerclient.Connection{}, fetcher, false)
		startDone <- err
	}()

	select {
	case <-fetcher.started:
	case <-time.After(2 * time.Second):
		t.Fatal("ApplyGitLabHostStart did not reach manager fetch within timeout")
	}

	if registeredJob(jr, id) != nil {
		t.Fatal("Job became visible during the half-published window")
	}
	if err := jr.StageCgroupBasenameForJob(testCtx, "docker-cafef00d.scope", id); !errors.Is(err, jobregistry.ErrJobNotFound) {
		t.Fatalf("StageCgroupBasenameForJob during host_start in-flight: got %v, want %v", err, jobregistry.ErrJobNotFound)
	}

	close(fetcher.release)
	if err := <-startDone; err != nil {
		t.Fatalf("ApplyGitLabHostStart: %v", err)
	}
	if registeredJob(jr, id) == nil {
		t.Fatal("expected Job to be visible after ApplyGitLabHostStart returned")
	}
}
