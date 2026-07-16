package joblogs

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	logv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

func TestMarshalRuntimeEventLogEntryAppliesProcessArgsRedactionPolicy(t *testing.T) {
	tests := []struct {
		name   string
		redact *bool
		assert func(*testing.T, *logv1beta1.EventRecord)
	}{
		{name: "nil policy defaults to sanitized output", assert: assertProtoEventProcessSanitized},
		{name: "explicit true sanitizes output", redact: boolPointer(true), assert: assertProtoEventProcessSanitized},
		{name: "explicit false preserves captured args", redact: boolPointer(false), assert: assertProtoEventProcessUnredacted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := eventWithSecretArgv()
			payload, err := MarshalRuntimeEventLogEntry(RuntimeEventLogInput{
				ScopeLogContext:   testScopeLogContext(),
				Event:             event,
				RedactProcessArgs: tt.redact,
			})
			if err != nil {
				t.Fatalf("marshal runtime event log: %v", err)
			}

			var got logv1beta1.RuntimeEventLogEntry
			if err := protojson.Unmarshal(payload, &got); err != nil {
				t.Fatalf("unmarshal runtime event log: %v", err)
			}
			tt.assert(t, got.GetEvent())
			if got, want := event.Process.Argv[1], "--token=supersecret"; got != want {
				t.Fatalf("input event argv mutated: got %q, want %q", got, want)
			}
			if got, want := event.Process.Ancestors[0].Argv[2], "Bearer abc123"; got != want {
				t.Fatalf("input ancestor argv mutated: got %q, want %q", got, want)
			}
		})
	}
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
