package joblogs

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

type RuntimeEventLogInput struct {
	ScopeLogContext
	Event jobevent.EventRecord
}

func MarshalRuntimeEventLogEntry(in RuntimeEventLogInput) ([]byte, error) {
	message := &logv1.RuntimeEventLogEntry{
		Timestamp:     timestamppb.New(in.Event.Timestamp.UTC()),
		LogType:       proto.String(string(logtype.RuntimeEvent)),
		SchemaVersion: proto.String(logtype.RuntimeEventSchemaVersion),
		AgentVersion:  proto.String(version.Current),
		LogId:         proto.String(newLogID()),
		Job:           protoconv.ToLogContext(in.Identity, in.Metadata),
		Scope:         proto.String(string(in.Scope)),
		RunnerType:    proto.String(in.RunnerType),
		Event:         sanitizedLogEventRecord(in.Event),
	}
	return logJSONMarshal.Marshal(message)
}
