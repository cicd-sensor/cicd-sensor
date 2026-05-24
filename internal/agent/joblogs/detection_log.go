package joblogs

import (
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

type DetectionLogInput struct {
	ScopeLogContext
	Hit                 *observations.HitEntry
	Event               jobevent.EventRecord
	RuleName            string
	RuleDescription     string
	RulesetRevision     string
	RuleAlertTruncation string
}

func MarshalDetectionLogEntry(in DetectionLogInput) ([]byte, error) {
	if in.Hit == nil {
		return nil, nil
	}
	rulesetRevision := in.Hit.RulesetRevision
	if rulesetRevision == "" {
		rulesetRevision = in.RulesetRevision
	}
	timestamp := in.Event.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	message := &logv1.DetectionLogEntry{
		Timestamp:           timestamppb.New(timestamp.UTC()),
		LogType:             proto.String(string(logtype.Detection)),
		SchemaVersion:       proto.String(logtype.DetectionSchemaVersion),
		AgentVersion:        proto.String(version.Current),
		LogId:               proto.String(newLogID()),
		Job:                 protoconv.ToLogContext(in.Identity, in.Metadata),
		Scope:               proto.String(string(in.Scope)),
		RunnerType:          proto.String(in.RunnerType),
		RulesetId:           proto.String(in.Hit.Identity.RulesetID),
		RuleId:              proto.String(in.Hit.Identity.RuleID),
		RulesetRevision:     proto.String(rulesetRevision),
		RuleName:            proto.String(in.RuleName),
		RuleDescription:     proto.String(in.RuleDescription),
		Action:              proto.String(in.Hit.Action),
		RuleAlertTruncation: proto.String(in.RuleAlertTruncation),
		Event:               sanitizedLogEventRecord(in.Event),
	}
	return logJSONMarshal.Marshal(message)
}
