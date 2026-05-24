package agent_test

import (
	"sync"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type recordingRuntimeEventOutput struct {
	mu      sync.Mutex
	payload [][]byte
}

func (s *recordingRuntimeEventOutput) Entries(t *testing.T) []*logv1.RuntimeEventLogEntry {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]*logv1.RuntimeEventLogEntry, 0, len(s.payload))
	for _, payload := range s.payload {
		entry := &logv1.RuntimeEventLogEntry{}
		if err := protojson.Unmarshal(payload, entry); err != nil {
			t.Fatalf("unmarshal runtime event entry: %v", err)
		}
		out = append(out, entry)
	}
	return out
}

func TestJobScopeStateWriteRuntimeEventLog_NoOpWhenManagerOutputNil(t *testing.T) {
	t.Parallel()

	scope := jobscope.NewHost()
	scope.WriteRuntimeEventLog(testCtx, testIdentity, testMetadata, "machine", testDispatchEvent("/usr/bin/curl", "example.com", 443), testLogger)
}

func TestJobScopeStateWriteRuntimeEventLog_EmitsEntryWithoutHits(t *testing.T) {
	t.Parallel()

	stream := &recordingRuntimeEventOutput{}
	scope := jobscope.NewHost()
	attachRecordingRuntimeEventOutput(t, scope, stream)
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	scope.WriteRuntimeEventLog(testCtx, testIdentity, testMetadata, "machine", event, testLogger)
	closeRecordingOutputs(t, scope)

	entries := stream.Entries(t)
	if len(entries) != 1 {
		t.Fatalf("entry count: got %d, want 1", len(entries))
	}
	if entries[0].GetScope() != string(jobcontext.ScopeTypeHost) {
		t.Fatalf("scope: got %q, want %q", entries[0].GetScope(), string(jobcontext.ScopeTypeHost))
	}
	if entries[0].Event.GetId() != event.ID {
		t.Fatalf("event id: got %q, want %q", entries[0].Event.GetId(), event.ID)
	}
}

func TestJobScopeStateWriteRuntimeEventLog_DoesNotEmbedHits(t *testing.T) {
	t.Parallel()

	stream := &recordingRuntimeEventOutput{}
	scope := jobscope.NewProject()
	attachRecordingRuntimeEventOutput(t, scope, stream)
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	scope.WriteRuntimeEventLog(testCtx, testIdentity, testMetadata, "machine", event, testLogger)
	closeRecordingOutputs(t, scope)

	entries := stream.Entries(t)
	if len(entries) != 1 {
		t.Fatalf("entry count: got %d, want 1", len(entries))
	}
	if entries[0].GetScope() != string(jobcontext.ScopeTypeProject) {
		t.Fatalf("scope: got %q, want %q", entries[0].GetScope(), string(jobcontext.ScopeTypeProject))
	}
	if entries[0].Event.GetNetworkConnect().GetRemoteIp() != "example.com" {
		t.Fatalf("event remote_ip: got %q, want example.com", entries[0].Event.GetNetworkConnect().GetRemoteIp())
	}
}

func TestJobScopeStateWriteRuntimeEventLog_NilReceiverNoOp(t *testing.T) {
	t.Parallel()

	var scope *jobscope.JobScopeState
	scope.WriteRuntimeEventLog(testCtx, testIdentity, testMetadata, "machine", testDispatchEvent("/usr/bin/curl", "example.com", 443), testLogger)
}
