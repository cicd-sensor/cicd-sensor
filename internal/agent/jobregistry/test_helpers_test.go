package jobregistry

import (
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

const testEventChannelSize = 4096

func newTestJob(identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, eventChannelSize int) (*job.Job, chan jobevent.EventRecord) {
	eventCh := make(chan jobevent.EventRecord, eventChannelSize)
	return job.NewJob(testLogger, identity, metadata, "machine", eventCh), eventCh
}

func sendTestEvent(t *testing.T, eventCh chan<- jobevent.EventRecord, event jobevent.EventRecord) {
	t.Helper()
	eventCh <- event
}

func waitForJob(t *testing.T, reason string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		<-ticker.C
	}
	t.Fatalf("timeout waiting: %s", reason)
}

func testDispatchEvent(execPath, host string, port int64) jobevent.EventRecord {
	return jobevent.EventRecord{
		EventType: jobevent.NetworkConnect,
		Timestamp: time.Date(2026, 4, 16, 1, 2, 3, 4, time.UTC),
		Payload: map[string]any{
			"remote_ip":   host,
			"remote_port": port,
			"protocol":    "tcp",
		},
		Process: jobevent.ProcessSummary{
			PID:      100,
			ExecPath: execPath,
		},
		Tags: map[string]string{},
	}
}
