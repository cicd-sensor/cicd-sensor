package joblogs

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

func TestMarshalRuntimeEventLogEntrySanitizesEventProcess(t *testing.T) {
	t.Parallel()

	payload, err := MarshalRuntimeEventLogEntry(RuntimeEventLogInput{
		ScopeLogContext: testScopeLogContext(),
		Event:           eventWithSecretArgv(),
	})
	if err != nil {
		t.Fatalf("marshal runtime event log: %v", err)
	}

	var got logv1.RuntimeEventLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal runtime event log: %v", err)
	}
	assertProtoEventProcessSanitized(t, got.GetEvent())
}

func TestMarshalRuntimeEventLogEntryStampsLogTypeAndVersions(t *testing.T) {
	t.Parallel()

	payload, err := MarshalRuntimeEventLogEntry(RuntimeEventLogInput{
		ScopeLogContext: testScopeLogContext(),
		Event:           eventWithSecretArgv(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got logv1.RuntimeEventLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.GetLogType() != string(logtype.RuntimeEvent) {
		t.Errorf("log_type: got %q, want %q", got.GetLogType(), string(logtype.RuntimeEvent))
	}
	if got.GetSchemaVersion() != "v1" {
		t.Errorf("schema_version: got %q, want %q", got.GetSchemaVersion(), "v1")
	}
	if got.GetAgentVersion() != version.Current {
		t.Errorf("agent_version: got %q, want %q", got.GetAgentVersion(), version.Current)
	}
}
