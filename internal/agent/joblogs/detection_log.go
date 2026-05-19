package joblogs

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
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
	message := &logv1.JobDetectionLogEntry{
		Timestamp:           timestamppb.New(timestamp.UTC()),
		LogId:               newLogID(),
		Job:                 protoconv.ToJobLogContext(in.Identity, in.Metadata, in.RunnerKind),
		Scope:               string(in.Scope),
		ConfigRevision:      in.ConfigRevision,
		RulesetId:           in.Hit.Identity.RulesetID,
		RuleId:              in.Hit.Identity.RuleID,
		RulesetRevision:     rulesetRevision,
		RuleName:            in.RuleName,
		RuleDescription:     in.RuleDescription,
		Action:              in.Hit.Action,
		RuleAlertTruncation: in.RuleAlertTruncation,
		Event:               sanitizedLogEventRecord(in.Event),
	}
	return logJSONMarshal.Marshal(message)
}
