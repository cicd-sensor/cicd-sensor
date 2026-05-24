package kerneltracker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

type recordingJobEndNotifier struct {
	ended []notifyJobEnded
}

func (notifier *recordingJobEndNotifier) OnJobEnded(jobID jobcontext.JobIdentity, reason EndReason) {
	notifier.ended = append(notifier.ended, notifyJobEnded{JobID: jobID, Reason: reason})
}

func TestKernelTrackerRun_ReturnsKernelSampleLoopError(t *testing.T) {
	t.Parallel()

	startErr := errors.New("start failed")
	kernelIO := &recordingKernelIO{startErr: startErr}
	engine := newTestKernelTracker(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, kernelIO, "")

	err := engine.Run(context.Background())
	if !errors.Is(err, startErr) {
		t.Fatalf("Run error = %v, want wrapped %v", err, startErr)
	}
	if kernelIO.startCalls != 1 {
		t.Fatalf("StartKernelSampleLoop calls = %d, want 1", kernelIO.startCalls)
	}
}

func TestKernelTrackerClose(t *testing.T) {
	t.Parallel()

	if err := (*KernelTracker)(nil).Close(); err != nil {
		t.Fatalf("nil Close error = %v, want nil", err)
	}
	if err := (&KernelTracker{}).Close(); err != nil {
		t.Fatalf("zero Close error = %v, want nil", err)
	}

	wantErr := errors.New("close failed")
	engine := newTestKernelTracker(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, &recordingKernelIO{closeErr: wantErr}, "")
	if err := engine.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("Close error = %v, want %v", err, wantErr)
	}
}

func TestRunEngineEffects_RecordsDroppedEvents(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.registerJob(jobID, 1)
	state.bind(jobID, 42)
	channel, ok := state.jobEventChannels[jobID]
	if !ok {
		t.Fatal("event channel missing")
	}
	channel <- jobevent.EventRecord{EventType: jobevent.FileOpen}

	engine := &KernelTracker{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		jobTracking: state,
	}

	engine.runEngineEffects(context.Background(), []engineEffect{emitEventRecord{
		JobID: jobID,
		Record: jobevent.EventRecord{
			EventType: jobevent.ProcessExec,
		},
	}})

	if got := engine.jobTracking.jobEventDropCounts[jobID]; got != 1 {
		t.Fatalf("event drop count for %q = %d, want 1", jobID, got)
	}
	if got := len(channel); got != 1 {
		t.Fatalf("channel len = %d, want 1", got)
	}
}

func TestRunEngineEffects_NotifyJobEnded(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "ended")
	engine := newTestKernelTracker(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, noopKernelIO{}, "")

	engine.runEngineEffects(context.Background(), []engineEffect{notifyJobEnded{
		JobID:  jobID,
		Reason: EndCgroupRmdir,
	}})

	notifier := &recordingJobEndNotifier{}
	engine.jobEndNotifier = notifier
	engine.runEngineEffects(context.Background(), []engineEffect{notifyJobEnded{
		JobID:  jobID,
		Reason: EndCgroupRmdir,
	}})

	if len(notifier.ended) != 1 {
		t.Fatalf("ended notifications = %d, want 1", len(notifier.ended))
	}
	if got := notifier.ended[0]; got.JobID != jobID || got.Reason != EndCgroupRmdir {
		t.Fatalf("notification = %#v, want job=%v reason=%v", got, jobID, EndCgroupRmdir)
	}
}

func TestDeleteJobKernelMapEntries_StagingDeleteFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("delete staging failed")
	kernelIO := &recordingKernelIO{deleteStagingErr: wantErr}
	var logs bytes.Buffer
	engine := newTestKernelTracker(slog.New(slog.NewJSONHandler(&logs, nil)), nil, kernelIO, "")

	err := engine.deleteJobKernelMapEntries(context.Background(), []uint64{42}, []string{"docker-cafef00d.scope"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("deleteJobKernelMapEntries error = %v, want %v", err, wantErr)
	}
	if !strings.Contains(logs.String(), "bpf_staging_entries_delete_failed") {
		t.Fatalf("staging delete failure was not logged: %s", logs.String())
	}
}
