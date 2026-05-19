package joblogs

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
)

func TestMarshalRuntimeTelemetryLogEntrySanitizesEventProcess(t *testing.T) {
	t.Parallel()

	payload, err := MarshalRuntimeTelemetryLogEntry(RuntimeTelemetryLogInput{
		ScopeLogContext: testScopeLogContext(),
		Event:           eventWithSecretArgv(),
	})
	if err != nil {
		t.Fatalf("marshal runtime telemetry log: %v", err)
	}

	var got logv1.JobRuntimeTelemetryLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal runtime telemetry log: %v", err)
	}
	assertProtoEventProcessSanitized(t, got.GetEvent())
}
