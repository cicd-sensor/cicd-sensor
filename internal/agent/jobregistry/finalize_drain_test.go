package jobregistry

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// lockedBuffer lets the drain goroutine log while the test reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newDrainTestRegistry(logs *lockedBuffer) *JobRegistry {
	jr := newTestJobRegistry()
	jr.logger = slog.New(slog.NewJSONHandler(logs, nil))
	return jr
}

func TestWaitForDrain_LogsProgressWhileWorkerIsStillRunning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs lockedBuffer
		jr := newDrainTestRegistry(&logs)
		identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
		// The channel stays open, so the worker is alive with an empty queue:
		// progress must be reported by time, not by queue length.
		j, eventCh := newTestJob(identity, jobcontext.JobMetadata{}, testEventChannelSize)

		done := make(chan struct{})
		go func() {
			defer close(done)
			jr.waitForDrain(testCtx, j)
		}()
		synctest.Wait()
		if strings.Contains(logs.String(), "job_drain_in_progress") {
			t.Fatal("progress must not be logged before the first interval")
		}

		time.Sleep(drainProgressInterval)
		synctest.Wait()
		got := logs.String()
		if !strings.Contains(got, `"msg":"job_drain_in_progress"`) || !strings.Contains(got, `"queued":0`) {
			t.Fatalf("expected one progress log with queued=0 after %s: %s", drainProgressInterval, got)
		}
		if strings.Contains(got, "job_drain_completed") {
			t.Fatalf("drain must not complete while the worker is running: %s", got)
		}

		close(eventCh)
		<-done
		got = logs.String()
		if strings.Count(got, `"msg":"job_drain_in_progress"`) != 1 {
			t.Fatalf("expected exactly one progress log: %s", got)
		}
		if !strings.Contains(got, `"msg":"job_drain_completed"`) || !strings.Contains(got, `"queued_at_start":0`) {
			t.Fatalf("expected completion log after the worker exited: %s", got)
		}
	})
}

func TestWaitForDrain_CompletesWithoutProgressWhenWorkerAlreadyExited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs lockedBuffer
		jr := newDrainTestRegistry(&logs)
		identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
		j, eventCh := newTestJob(identity, jobcontext.JobMetadata{}, testEventChannelSize)
		close(eventCh)
		<-j.Done()

		jr.waitForDrain(testCtx, j)

		got := logs.String()
		if !strings.Contains(got, `"msg":"job_drain_completed"`) {
			t.Fatalf("expected completion log: %s", got)
		}
		if strings.Contains(got, "job_drain_in_progress") {
			t.Fatalf("no progress log expected for an already drained worker: %s", got)
		}
	})
}
