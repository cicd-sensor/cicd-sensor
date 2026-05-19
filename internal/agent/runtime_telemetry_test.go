package agent_test

import (
	"sync"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type recordingRuntimeTelemetryOutput struct {
	mu      sync.Mutex
	payload [][]byte
}

func (s *recordingRuntimeTelemetryOutput) Entries(t *testing.T) []logv1.JobRuntimeTelemetryLogEntry {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]logv1.JobRuntimeTelemetryLogEntry, 0, len(s.payload))
	for _, payload := range s.payload {
		var entry logv1.JobRuntimeTelemetryLogEntry
		if err := protojson.Unmarshal(payload, &entry); err != nil {
			t.Fatalf("unmarshal runtime telemetry entry: %v", err)
		}
		out = append(out, entry)
	}
	return out
}

func TestJobScopeStateWriteRuntimeTelemetryLog_NoOpWhenManagerOutputNil(t *testing.T) {
	t.Parallel()

	scope := jobscope.NewHost()
	scope.WriteRuntimeTelemetryLog(testCtx, testIdentity, testMetadata, "machine", testDispatchEvent("/usr/bin/curl", "example.com", 443), testLogger)
}

func TestJobScopeStateWriteRuntimeTelemetryLog_EmitsEntryWithoutHits(t *testing.T) {
	t.Parallel()

	stream := &recordingRuntimeTelemetryOutput{}
	scope := jobscope.NewHost()
	attachRecordingRuntimeTelemetryOutput(t, scope, stream)
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	scope.WriteRuntimeTelemetryLog(testCtx, testIdentity, testMetadata, "machine", event, testLogger)
	closeRecordingOutputs(t, scope)

	entries := stream.Entries(t)
	if len(entries) != 1 {
		t.Fatalf("entry count: got %d, want 1", len(entries))
	}
	if entries[0].Scope != string(jobcontext.ScopeKindHost) {
		t.Fatalf("scope: got %q, want %q", entries[0].Scope, string(jobcontext.ScopeKindHost))
	}
	if entries[0].Event.GetId() != event.ID {
		t.Fatalf("event id: got %q, want %q", entries[0].Event.GetId(), event.ID)
	}
}

func TestJobScopeStateWriteRuntimeTelemetryLog_DoesNotEmbedHits(t *testing.T) {
	t.Parallel()

	stream := &recordingRuntimeTelemetryOutput{}
	scope := jobscope.NewProject()
	attachRecordingRuntimeTelemetryOutput(t, scope, stream)
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	scope.WriteRuntimeTelemetryLog(testCtx, testIdentity, testMetadata, "machine", event, testLogger)
	closeRecordingOutputs(t, scope)

	entries := stream.Entries(t)
	if len(entries) != 1 {
		t.Fatalf("entry count: got %d, want 1", len(entries))
	}
	if entries[0].Scope != string(jobcontext.ScopeKindProject) {
		t.Fatalf("scope: got %q, want %q", entries[0].Scope, string(jobcontext.ScopeKindProject))
	}
	if entries[0].Event.GetNetworkConnect().GetRemoteIp() != "example.com" {
		t.Fatalf("event remote_ip: got %q, want example.com", entries[0].Event.GetNetworkConnect().GetRemoteIp())
	}
}

func TestJobScopeStateWriteRuntimeTelemetryLog_NilReceiverNoOp(t *testing.T) {
	t.Parallel()

	var scope *jobscope.JobScopeState
	scope.WriteRuntimeTelemetryLog(testCtx, testIdentity, testMetadata, "machine", testDispatchEvent("/usr/bin/curl", "example.com", 443), testLogger)
}
