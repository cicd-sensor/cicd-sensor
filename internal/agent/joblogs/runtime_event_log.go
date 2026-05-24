package joblogs

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	logv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

type RuntimeEventLogInput struct {
	ScopeLogContext
	Event jobevent.EventRecord
}

func MarshalRuntimeEventLogEntry(in RuntimeEventLogInput) ([]byte, error) {
	message := &logv1beta1.RuntimeEventLogEntry{
		Timestamp:      timestamppb.New(in.Event.Timestamp.UTC()),
		LogType:        proto.String(logtype.RuntimeEvent.Wire()),
		ServiceName:    proto.String(logtype.ServiceName),
		ServiceVersion: proto.String(version.Current),
		SchemaVersion:  proto.String(logtype.RuntimeEventSchemaVersion),
		LogId:          proto.String(newLogID()),
		Job:            protoconv.ToLogContext(in.Identity, in.Metadata),
		Scope:          proto.String(string(in.Scope)),
		RunnerType:     proto.String(in.RunnerType),
		Event:          sanitizedLogEventRecord(in.Event),
	}
	return logJSONMarshal.Marshal(message)
}
