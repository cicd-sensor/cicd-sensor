package jobregistry

import (
	"bytes"
	"context"
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

func TestWaitForDrain_DeadlinePath(t *testing.T) {
	tests := []struct {
		name string
		// stallWorker leaves the event channel open so Done() never fires.
		stallWorker bool
		// expireBeforeWait cancels ctx before waitForDrain runs.
		expireBeforeWait bool
		// grace is the ctx timeout when the deadline must fire during the wait.
		grace       time.Duration
		advance     time.Duration
		wantMsg     string
		wantQueued  string
		wantElapsed bool
		rejectMsg   string
	}{
		{
			name:        "deadline: stalled worker truncates so finalize can continue",
			stallWorker: true,
			grace:       time.Second,
			advance:     time.Second,
			wantMsg:     "job_drain_truncated",
			wantQueued:  `"queued":0`,
			wantElapsed: true,
			rejectMsg:   "job_drain_completed",
		},
		{
			name:             "deadline: already-expired ctx truncates immediately",
			stallWorker:      true,
			expireBeforeWait: true,
			wantMsg:          "job_drain_truncated",
			wantQueued:       `"queued":0`,
			wantElapsed:      true,
			rejectMsg:        "job_drain_completed",
		},
		{
			// Both channels are ready: Done must win so a finished drain is
			// not mis-logged as truncated.
			name:             "deadline: already-drained with expired ctx logs completed",
			stallWorker:      false,
			expireBeforeWait: true,
			wantMsg:          "job_drain_completed",
			rejectMsg:        "job_drain_truncated",
		},
		{
			name:        "happy: worker finishes before deadline logs completed",
			stallWorker: false,
			grace:       time.Minute,
			wantMsg:     "job_drain_completed",
			rejectMsg:   "job_drain_truncated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				var logs lockedBuffer
				jr := newDrainTestRegistry(&logs)
				identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
				j, eventCh := newTestJob(identity, jobcontext.JobMetadata{}, testEventChannelSize)

				ctx := context.Background()
				cancel := func() {}
				switch {
				case tt.expireBeforeWait:
					ctx, cancel = context.WithCancel(context.Background())
					cancel()
				case tt.grace > 0:
					ctx, cancel = context.WithTimeout(context.Background(), tt.grace)
				}
				defer cancel()

				if !tt.stallWorker {
					close(eventCh)
					<-j.Done()
					jr.waitForDrain(ctx, j)
				} else {
					done := make(chan struct{})
					go func() {
						defer close(done)
						jr.waitForDrain(ctx, j)
					}()
					if tt.advance > 0 {
						synctest.Wait()
						time.Sleep(tt.advance)
						synctest.Wait()
					}
					<-done
					close(eventCh)
				}

				got := logs.String()
				if !strings.Contains(got, `"msg":"`+tt.wantMsg+`"`) {
					t.Fatalf("expected %s log: %s", tt.wantMsg, got)
				}
				if tt.wantQueued != "" && !strings.Contains(got, tt.wantQueued) {
					t.Fatalf("expected %s in log: %s", tt.wantQueued, got)
				}
				if tt.wantElapsed && !strings.Contains(got, `"elapsed_ms":`) {
					t.Fatalf("expected elapsed_ms in truncated log: %s", got)
				}
				if tt.rejectMsg != "" && strings.Contains(got, tt.rejectMsg) {
					t.Fatalf("did not want %s: %s", tt.rejectMsg, got)
				}
			})
		})
	}
}
