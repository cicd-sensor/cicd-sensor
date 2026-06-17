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

	if got := len(channel); got != 1 {
		t.Fatalf("channel len = %d, want 1", got)
	}
	stats := engine.jobTracking.jobEventDeliveryStats[jobID][jobevent.ProcessExec]
	if stats == nil {
		t.Fatal("process_exec delivery stats missing")
	}
	if stats.Attempted != 1 || stats.Delivered != 0 || stats.Dropped != 1 || stats.SuppressedDuplicates != 0 || stats.MaxQueueDepth != 1 {
		t.Fatalf("process_exec stats = %#v, want attempted=1 delivered=0 dropped=1 suppressed=0 max_queue_depth=1", stats)
	}
}

func TestRunEngineEffects_SuppressesRepeatedFileOpenAfterFirstDelivery(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.registerJob(jobID, 4)
	engine := &KernelTracker{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		jobTracking: state,
	}
	record := testFileOpenEventRecord("/workspace/secret.txt")

	engine.runEngineEffects(context.Background(), []engineEffect{
		emitEventRecord{JobID: jobID, Record: record},
		emitEventRecord{JobID: jobID, Record: record},
	})

	channel := state.jobEventChannels[jobID]
	if got := len(channel); got != 1 {
		t.Fatalf("channel len = %d, want 1", got)
	}
	stats := state.jobEventDeliveryStats[jobID][jobevent.FileOpen]
	if stats == nil {
		t.Fatal("file_open delivery stats missing")
	}
	if stats.Attempted != 2 || stats.Delivered != 1 || stats.Dropped != 0 || stats.SuppressedDuplicates != 1 {
		t.Fatalf("file_open stats = %#v, want attempted=2 delivered=1 dropped=0 suppressed=1", stats)
	}
}

func TestRunEngineEffects_DoesNotRememberFileOpenKeyWhenEnqueueFails(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.registerJob(jobID, 1)
	channel := state.jobEventChannels[jobID]
	channel <- jobevent.EventRecord{EventType: jobevent.ProcessExec}
	engine := &KernelTracker{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		jobTracking: state,
	}
	record := testFileOpenEventRecord("/workspace/secret.txt")

	engine.runEngineEffects(context.Background(), []engineEffect{
		emitEventRecord{JobID: jobID, Record: record},
	})
	<-channel
	engine.runEngineEffects(context.Background(), []engineEffect{
		emitEventRecord{JobID: jobID, Record: record},
	})

	if got := len(channel); got != 1 {
		t.Fatalf("channel len = %d, want 1", got)
	}
	got := <-channel
	if got.EventType != jobevent.FileOpen {
		t.Fatalf("delivered event type = %q, want %q", got.EventType, jobevent.FileOpen)
	}
	stats := state.jobEventDeliveryStats[jobID][jobevent.FileOpen]
	if stats == nil {
		t.Fatal("file_open delivery stats missing")
	}
	if stats.Attempted != 2 || stats.Delivered != 1 || stats.Dropped != 1 || stats.SuppressedDuplicates != 0 {
		t.Fatalf("file_open stats = %#v, want attempted=2 delivered=1 dropped=1 suppressed=0", stats)
	}
}

func TestRunEngineEffects_DeliversUniqueFileOpenEvents(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.registerJob(jobID, 4)
	engine := &KernelTracker{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		jobTracking: state,
	}

	engine.runEngineEffects(context.Background(), []engineEffect{
		emitEventRecord{JobID: jobID, Record: testFileOpenEventRecord("/workspace/a.txt")},
		emitEventRecord{JobID: jobID, Record: testFileOpenEventRecord("/workspace/b.txt")},
	})

	channel := state.jobEventChannels[jobID]
	if got := len(channel); got != 2 {
		t.Fatalf("channel len = %d, want 2", got)
	}
	stats := state.jobEventDeliveryStats[jobID][jobevent.FileOpen]
	if stats == nil {
		t.Fatal("file_open delivery stats missing")
	}
	if stats.Attempted != 2 || stats.Delivered != 2 || stats.Dropped != 0 || stats.SuppressedDuplicates != 0 {
		t.Fatalf("file_open stats = %#v, want attempted=2 delivered=2 dropped=0 suppressed=0", stats)
	}
}

func TestRunEngineEffects_DeliversFileOpenEventsWithDifferentFlags(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.registerJob(jobID, 4)
	engine := &KernelTracker{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		jobTracking: state,
	}

	first := testFileOpenEventRecord("/workspace/secret.txt")
	second := testFileOpenEventRecord("/workspace/secret.txt")
	second.Payload[fileOpenPayloadFlags] = 0x241
	engine.runEngineEffects(context.Background(), []engineEffect{
		emitEventRecord{JobID: jobID, Record: first},
		emitEventRecord{JobID: jobID, Record: second},
	})

	channel := state.jobEventChannels[jobID]
	if got := len(channel); got != 2 {
		t.Fatalf("channel len = %d, want 2", got)
	}
	stats := state.jobEventDeliveryStats[jobID][jobevent.FileOpen]
	if stats == nil {
		t.Fatal("file_open delivery stats missing")
	}
	if stats.Attempted != 2 || stats.Delivered != 2 || stats.Dropped != 0 || stats.SuppressedDuplicates != 0 {
		t.Fatalf("file_open stats = %#v, want attempted=2 delivered=2 dropped=0 suppressed=0", stats)
	}
}

func TestRunEngineEffects_DeliversReadAfterRepeatedWriteFileOpen(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.registerJob(jobID, 4)
	engine := &KernelTracker{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		jobTracking: state,
	}

	writeRecord := testFileOpenEventRecord("/workspace/secret.txt")
	writeRecord.Payload[fileOpenPayloadIsRead] = false
	writeRecord.Payload[fileOpenPayloadIsWrite] = true
	writeRecord.Payload[fileOpenPayloadFlags] = 0x1
	readRecord := testFileOpenEventRecord("/workspace/secret.txt")
	engine.runEngineEffects(context.Background(), []engineEffect{
		emitEventRecord{JobID: jobID, Record: writeRecord},
		emitEventRecord{JobID: jobID, Record: writeRecord},
		emitEventRecord{JobID: jobID, Record: readRecord},
	})

	channel := state.jobEventChannels[jobID]
	if got := len(channel); got != 2 {
		t.Fatalf("channel len = %d, want 2", got)
	}
	first := <-channel
	second := <-channel
	if first.Payload[fileOpenPayloadIsWrite] != true || second.Payload[fileOpenPayloadIsRead] != true {
		t.Fatalf("delivered payloads = %#v, %#v; want write then read", first.Payload, second.Payload)
	}
	stats := state.jobEventDeliveryStats[jobID][jobevent.FileOpen]
	if stats == nil {
		t.Fatal("file_open delivery stats missing")
	}
	if stats.Attempted != 3 || stats.Delivered != 2 || stats.Dropped != 0 || stats.SuppressedDuplicates != 1 {
		t.Fatalf("file_open stats = %#v, want attempted=3 delivered=2 dropped=0 suppressed=1", stats)
	}
}

func TestRunEngineEffects_DeliversRepeatedTruncatedFileOpenEvents(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.registerJob(jobID, 4)
	engine := &KernelTracker{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		jobTracking: state,
	}
	record := testFileOpenEventRecord("/workspace/truncated.txt")
	record.Tags = map[string]string{"truncated": "path"}

	engine.runEngineEffects(context.Background(), []engineEffect{
		emitEventRecord{JobID: jobID, Record: record},
		emitEventRecord{JobID: jobID, Record: record},
	})

	channel := state.jobEventChannels[jobID]
	if got := len(channel); got != 2 {
		t.Fatalf("channel len = %d, want 2", got)
	}
	stats := state.jobEventDeliveryStats[jobID][jobevent.FileOpen]
	if stats == nil {
		t.Fatal("file_open delivery stats missing")
	}
	if stats.Attempted != 2 || stats.Delivered != 2 || stats.Dropped != 0 || stats.SuppressedDuplicates != 0 {
		t.Fatalf("file_open stats = %#v, want attempted=2 delivered=2 dropped=0 suppressed=0", stats)
	}
}

func TestRunEngineEffects_FileOpenDedupIsPerJob(t *testing.T) {
	t.Parallel()

	firstJob := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	secondJob := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "456")
	state := newJobTrackingState()
	state.registerJob(firstJob, 4)
	state.registerJob(secondJob, 4)
	engine := &KernelTracker{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		jobTracking: state,
	}
	record := testFileOpenEventRecord("/workspace/shared.txt")

	engine.runEngineEffects(context.Background(), []engineEffect{
		emitEventRecord{JobID: firstJob, Record: record},
		emitEventRecord{JobID: secondJob, Record: record},
		emitEventRecord{JobID: firstJob, Record: record},
		emitEventRecord{JobID: secondJob, Record: record},
	})

	firstChannel := state.jobEventChannels[firstJob]
	secondChannel := state.jobEventChannels[secondJob]
	if got := len(firstChannel); got != 1 {
		t.Fatalf("first job channel len = %d, want 1", got)
	}
	if got := len(secondChannel); got != 1 {
		t.Fatalf("second job channel len = %d, want 1", got)
	}
	firstStats := state.jobEventDeliveryStats[firstJob][jobevent.FileOpen]
	if firstStats == nil {
		t.Fatal("first job file_open delivery stats missing")
	}
	if firstStats.Attempted != 2 || firstStats.Delivered != 1 || firstStats.Dropped != 0 || firstStats.SuppressedDuplicates != 1 {
		t.Fatalf("first job file_open stats = %#v, want attempted=2 delivered=1 dropped=0 suppressed=1", firstStats)
	}
	secondStats := state.jobEventDeliveryStats[secondJob][jobevent.FileOpen]
	if secondStats == nil {
		t.Fatal("second job file_open delivery stats missing")
	}
	if secondStats.Attempted != 2 || secondStats.Delivered != 1 || secondStats.Dropped != 0 || secondStats.SuppressedDuplicates != 1 {
		t.Fatalf("second job file_open stats = %#v, want attempted=2 delivered=1 dropped=0 suppressed=1", secondStats)
	}
}

func TestRunEngineEffects_DeliversProcessExecAfterRepeatedFileOpen(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.registerJob(jobID, 2)
	engine := &KernelTracker{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		jobTracking: state,
	}

	effects := make([]engineEffect, 0, 101)
	for range 100 {
		effects = append(effects, emitEventRecord{JobID: jobID, Record: testFileOpenEventRecord("/workspace/secret.txt")})
	}
	effects = append(effects, emitEventRecord{JobID: jobID, Record: jobevent.EventRecord{EventType: jobevent.ProcessExec}})

	engine.runEngineEffects(context.Background(), effects)

	channel := state.jobEventChannels[jobID]
	if got := len(channel); got != 2 {
		t.Fatalf("channel len = %d, want 2", got)
	}
	first := <-channel
	second := <-channel
	if first.EventType != jobevent.FileOpen || second.EventType != jobevent.ProcessExec {
		t.Fatalf("delivered event types = %q, %q; want file_open, process_exec", first.EventType, second.EventType)
	}
	fileStats := state.jobEventDeliveryStats[jobID][jobevent.FileOpen]
	if fileStats == nil {
		t.Fatal("file_open delivery stats missing")
	}
	if fileStats.Attempted != 100 || fileStats.Delivered != 1 || fileStats.SuppressedDuplicates != 99 || fileStats.Dropped != 0 {
		t.Fatalf("file_open stats = %#v, want attempted=100 delivered=1 suppressed=99 dropped=0", fileStats)
	}
	processStats := state.jobEventDeliveryStats[jobID][jobevent.ProcessExec]
	if processStats == nil {
		t.Fatal("process_exec delivery stats missing")
	}
	if processStats.Attempted != 1 || processStats.Delivered != 1 || processStats.Dropped != 0 || processStats.SuppressedDuplicates != 0 {
		t.Fatalf("process_exec stats = %#v, want attempted=1 delivered=1 dropped=0 suppressed=0", processStats)
	}
}

func TestRunEngineEffects_RemoveJobLogsDeliverySummary(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.registerJob(jobID, 1)
	state.jobEventDeliveryStats[jobID] = map[jobevent.Type]*eventDeliveryStats{
		jobevent.FileOpen: {
			Attempted:            3,
			Delivered:            1,
			SuppressedDuplicates: 2,
			MaxQueueDepth:        1,
		},
		jobevent.ProcessExec: {
			Attempted: 1,
			Delivered: 1,
		},
	}
	var logs bytes.Buffer
	engine := &KernelTracker{
		logger:      slog.New(slog.NewJSONHandler(&logs, nil)),
		kernelIO:    noopKernelIO{},
		jobTracking: state,
	}

	engine.runEngineEffects(context.Background(), []engineEffect{removeJobFromKernel{JobID: jobID}})

	got := logs.String()
	if !strings.Contains(got, "kernel_event_delivery_summary") {
		t.Fatalf("delivery summary was not logged: %s", got)
	}
	if !strings.Contains(got, `"event_type":"file_open"`) {
		t.Fatalf("delivery summary did not include file_open: %s", got)
	}
	if strings.Contains(got, `"event_type":"process_exec"`) {
		t.Fatalf("delivery summary should skip event types without drop or suppression: %s", got)
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

func testFileOpenEventRecord(path string) jobevent.EventRecord {
	return jobevent.EventRecord{
		EventType: jobevent.FileOpen,
		Process: jobevent.ProcessSummary{
			PID:           123,
			StartBoottime: 456,
			ExecPath:      "/usr/bin/cat",
		},
		Payload: map[string]any{
			fileOpenPayloadPath:    path,
			fileOpenPayloadIsRead:  true,
			fileOpenPayloadIsWrite: false,
			fileOpenPayloadFlags:   0,
		},
	}
}
