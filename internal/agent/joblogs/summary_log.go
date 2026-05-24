package joblogs

import (
	"slices"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

type SummaryLogInput struct {
	ScopeLogContext
	RuleModifiers  []rule.RuleModifier
	ResolvedRules  rule.ResolvedRules
	Snapshot       observations.StateSnapshot
	FinalizeReason string
	StartedAt      time.Time
	FinalizedAt    time.Time
}

func MarshalSummaryLogEntry(in SummaryLogInput) ([]byte, error) {
	finalizedAt := in.FinalizedAt
	if finalizedAt.IsZero() {
		finalizedAt = time.Now()
	}
	var startTimePB, endTimePB *timestamppb.Timestamp
	var durationS *int64
	endTimePB = timestamppb.New(finalizedAt.UTC())
	if !in.StartedAt.IsZero() {
		startTimePB = timestamppb.New(in.StartedAt.UTC())
		secs := int64(finalizedAt.Sub(in.StartedAt).Seconds())
		durationS = proto.Int64(secs)
	}
	message := &logv1.SummaryLogEntry{
		Timestamp:       timestamppb.New(finalizedAt.UTC()),
		LogType:         proto.String(string(logtype.Summary)),
		SchemaVersion:   proto.String(logtype.SummarySchemaVersion),
		AgentVersion:    proto.String(version.Current),
		LogId:           proto.String(newLogID()),
		Job:             protoconv.ToLogContext(in.Identity, in.Metadata),
		Scope:           proto.String(string(in.Scope)),
		RunnerType:      proto.String(in.RunnerType),
		ConfigRevision:  proto.String(configRevisionOrAbsent(in.ConfigRevision)),
		Rulesets:        rulesetUseProtos(in.ResolvedRules.Rules),
		RuleModifiers:   ruleModifierUseProtos(in.RuleModifiers),
		NetworkConnects: networkConnects(in.Snapshot.ObservationNetwork.Records),
		Domains:         domains(in.Snapshot.ObservationDomain.Records),
		Detections:      detectedRuleSummaryProtos(in.Snapshot),
		EventsTotal:     proto.Uint32(uint32Counter(in.Snapshot.Counters.EventsTotal)),
		EventsDropped:   proto.Uint32(uint32Counter(in.Snapshot.Counters.EventsDropped)),
		StartTime:       startTimePB,
		EndTime:         endTimePB,
		DurationS:       durationS,
		FinalizeReason:  proto.String(in.FinalizeReason),
	}
	return logJSONMarshal.Marshal(message)
}

func networkConnects(records []observations.NetworkObservationRecord) []string {
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.RemoteIP == "" {
			continue
		}
		seen[record.RemoteIP] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	slices.Sort(out)
	return out
}

func domains(records []observations.DomainObservationRecord) []string {
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.Domain == "" {
			continue
		}
		seen[record.Domain] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for domain := range seen {
		out = append(out, domain)
	}
	slices.Sort(out)
	return out
}

func rulesetUseProtos(rules []rule.ResolvedRule) []*logv1.RulesetUse {
	out := make([]*logv1.RulesetUse, 0, len(rules))
	seen := make(map[rulesetUseKey]struct{}, len(rules))
	for _, resolved := range rules {
		if resolved.RulesetID == "" {
			continue
		}
		key := rulesetUseKey{rulesetID: resolved.RulesetID, revision: resolved.RulesetRevision}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, &logv1.RulesetUse{RulesetId: proto.String(resolved.RulesetID), Revision: proto.String(resolved.RulesetRevision)})
	}
	return out
}

type rulesetUseKey struct {
	rulesetID string
	revision  string
}

func ruleModifierUseProtos(modifiers []rule.RuleModifier) []*logv1.RuleModifierUse {
	out := make([]*logv1.RuleModifierUse, 0, len(modifiers))
	for _, modifier := range modifiers {
		if modifier.ModifierID == "" {
			continue
		}
		out = append(out, &logv1.RuleModifierUse{ModifierId: proto.String(modifier.ModifierID), Revision: proto.String(modifier.Revision)})
	}
	return out
}

func detectedRuleSummaryProtos(snapshot observations.StateSnapshot) []*logv1.DetectedRuleSummary {
	out := make([]*logv1.DetectedRuleSummary, 0, len(snapshot.Hits))
	for _, hit := range snapshot.Hits {
		out = append(out, &logv1.DetectedRuleSummary{
			RulesetId:       proto.String(hit.RulesetID),
			RuleId:          proto.String(hit.RuleID),
			RulesetRevision: proto.String(hit.RulesetRevision),
			Action:          proto.String(hit.Action),
			Count:           proto.Uint32(uint32Counter(hit.HitCount)),
		})
	}
	return out
}
