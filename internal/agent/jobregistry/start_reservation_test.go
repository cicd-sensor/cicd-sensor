package jobregistry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
)

type fakeManagerFetcher struct{}

func (fakeManagerFetcher) FetchConfig(context.Context, *managerv1beta1.FetchConfigRequest) (*managerclient.FetchResult, error) {
	return &managerclient.FetchResult{}, nil
}

func TestWaitForJobStartReservation_ContextCancel(t *testing.T) {
	jr := newTestJobRegistry()
	id := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	reservation := jr.reserveJobStart(id)
	defer reservation.done()

	ctx, cancel := context.WithCancel(testCtx)
	cancel()

	_, err := jr.waitForJobStartReservation(ctx, id)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForJobStartReservation error: got %v, want context.Canceled", err)
	}
}

func TestApplyGitLabHostStart_WaitsForInflightStart(t *testing.T) {
	fetcher := &blockingManagerFetcher{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	jr := newTestJobRegistry()
	id := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	meta := jobcontext.JobMetadata{}

	startDone := make(chan error, 1)
	go func() {
		_, err := jr.ApplyGitLabHostStart(testCtx, id, meta, "machine", managerclient.Connection{}, fetcher)
		startDone <- err
	}()

	select {
	case <-fetcher.started:
	case <-time.After(2 * time.Second):
		t.Fatal("ApplyGitLabHostStart did not reach manager fetch within timeout")
	}

	waitDone := make(chan error, 1)
	go func() {
		_, err := jr.ApplyGitLabHostStart(testCtx, id, meta, "machine", managerclient.Connection{}, nil)
		waitDone <- err
	}()

	select {
	case err := <-waitDone:
		t.Fatalf("second ApplyGitLabHostStart returned before first completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(fetcher.release)
	if err := <-startDone; err != nil {
		t.Fatalf("first ApplyGitLabHostStart: %v", err)
	}
	if err := <-waitDone; err != nil {
		t.Fatalf("second ApplyGitLabHostStart: %v", err)
	}
}

type blockingManagerFetcher struct {
	started chan struct{}
	release chan struct{}
}

func (f *blockingManagerFetcher) FetchConfig(ctx context.Context, _ *managerv1beta1.FetchConfigRequest) (*managerclient.FetchResult, error) {
	close(f.started)
	select {
	case <-f.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &managerclient.FetchResult{}, nil
}
