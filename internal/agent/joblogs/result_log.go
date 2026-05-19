package joblogs

import (
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

type JobResultLogInput struct {
	ScopeLogContext
	RuleModifiers  []rule.RuleModifier
	ResolvedRules  rule.ResolvedRules
	Snapshot       observations.StateSnapshot
	FinalizeReason string
	FinalizedAt    time.Time
}

func MarshalJobResultLogEntry(in JobResultLogInput) ([]byte, error) {
	finalizedAt := in.FinalizedAt
	if finalizedAt.IsZero() {
		finalizedAt = time.Now()
	}
	message := &logv1.JobResultLogEntry{
		Timestamp:       timestamppb.New(finalizedAt.UTC()),
		LogId:           newLogID(),
		Job:             protoconv.ToJobLogContext(in.Identity, in.Metadata, in.RunnerKind),
		Scope:           string(in.Scope),
		ConfigRevision:  in.ConfigRevision,
		Rulesets:        rulesetUseProtos(in.ResolvedRules.Rules),
		RuleModifiers:   ruleModifierUseProtos(in.RuleModifiers),
		NetworkConnects: networkConnects(in.Snapshot.ObservationNetwork.Records),
		Domains:         domains(in.Snapshot.ObservationDomain.Records),
		Detections:      detectedRuleSummaryProtos(in.Snapshot),
		EventsTotal:     uint64Counter(in.Snapshot.Counters.EventsTotal),
		EventsDropped:   uint64Counter(in.Snapshot.Counters.EventsDropped),
		FinalizeReason:  in.FinalizeReason,
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
		out = append(out, &logv1.RulesetUse{RulesetId: resolved.RulesetID, Revision: resolved.RulesetRevision})
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
		out = append(out, &logv1.RuleModifierUse{ModifierId: modifier.ModifierID, Revision: modifier.Revision})
	}
	return out
}

func detectedRuleSummaryProtos(snapshot observations.StateSnapshot) []*logv1.DetectedRuleSummary {
	out := make([]*logv1.DetectedRuleSummary, 0, len(snapshot.Hits))
	for _, hit := range snapshot.Hits {
		out = append(out, &logv1.DetectedRuleSummary{
			RulesetId:       hit.RulesetID,
			RuleId:          hit.RuleID,
			RulesetRevision: hit.RulesetRevision,
			Action:          hit.Action,
			Count:           uint64(hit.HitCount),
		})
	}
	return out
}
