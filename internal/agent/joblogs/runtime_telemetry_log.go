package joblogs

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
)

type RuntimeTelemetryLogInput struct {
	ScopeLogContext
	Event jobevent.EventRecord
}

func MarshalRuntimeTelemetryLogEntry(in RuntimeTelemetryLogInput) ([]byte, error) {
	message := &logv1.JobRuntimeTelemetryLogEntry{
		Timestamp:      timestamppb.New(in.Event.Timestamp.UTC()),
		LogId:          newLogID(),
		Job:            protoconv.ToJobLogContext(in.Identity, in.Metadata, in.RunnerKind),
		Scope:          string(in.Scope),
		ConfigRevision: in.ConfigRevision,
		Event:          sanitizedLogEventRecord(in.Event),
	}
	return logJSONMarshal.Marshal(message)
}
