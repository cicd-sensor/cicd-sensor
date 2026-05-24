package joblogs

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	logv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1beta1"
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

	var got logv1beta1.RuntimeEventLogEntry
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
	var got logv1beta1.RuntimeEventLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.GetLogType() != logtype.RuntimeEvent.Wire() {
		t.Errorf("log_type: got %q, want %q", got.GetLogType(), logtype.RuntimeEvent.Wire())
	}
	if got.GetServiceName() != "cicd-sensor" {
		t.Errorf("service_name: got %q, want %q", got.GetServiceName(), "cicd-sensor")
	}
	if got.GetSchemaVersion() != "v1" {
		t.Errorf("schema_version: got %q, want %q", got.GetSchemaVersion(), "v1")
	}
	if got.GetServiceVersion() != version.Current {
		t.Errorf("service_version: got %q, want %q", got.GetServiceVersion(), version.Current)
	}
}
