package projectresult

import (
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

type ReportDocumentInput struct {
	Identity       jobcontext.JobIdentity
	Metadata       jobcontext.JobMetadata
	RunnerType     string
	StartedAt      time.Time
	GeneratedAt    time.Time
	FinalizeReason string
	ResolvedRules  rule.ResolvedRules
	Snapshot       observations.StateSnapshot
}

func BuildJobEventSummaryForReport(in ReportDocumentInput) resultdoc.JobEventSummaryForReport {
	ruleDetails := make(map[rule.RuleIdentity]ruleDetail, len(in.ResolvedRules.Rules))
	for _, resolved := range in.ResolvedRules.Rules {
		ruleDetails[resolved.Identity()] = ruleDetail{
			name:      resolved.Rule.RuleName,
			ruleType:  resultRuleType(resolved.Rule.Type),
			condition: resolved.Rule.Condition,
		}
	}

	hits := make([]resultdoc.HitRecord, 0)
	result := resultdoc.ResultNoAlert
	for _, hit := range in.Snapshot.Hits {
		switch hit.Action {
		case string(rule.RuleActionTerminate):
			result = resultdoc.ResultTerminated
		case string(rule.RuleActionDetect):
			if result != resultdoc.ResultTerminated {
				result = resultdoc.ResultDetected
			}
		}
		dropped := hit.HitCount - int64(len(hit.AlertEventRecords))
		for i, event := range hit.AlertEventRecords {
			detail := ruleDetails[hit.Identity]
			process := resultProcessSummary(jobevent.RedactProcessSummaryForOutput(event.Process))
			rec := resultdoc.HitRecord{
				Timestamp:     event.Timestamp,
				RulesetID:     hit.RulesetID,
				RuleID:        hit.RuleID,
				RuleName:      detail.name,
				RuleType:      detail.ruleType,
				RuleCondition: detail.condition,
				Action:        hit.Action,
				EventType:     event.EventType,
				Process:       &process,
				Payload:       event.Payload,
			}
			if dropped > 0 && i == len(hit.AlertEventRecords)-1 {
				rec.AlertTruncation = resultdoc.AlertTruncationMaxAlertsReached
				rec.AlertCap = hit.MaxAlerts
				rec.AlertDropped = dropped
			}
			hits = append(hits, rec)
		}
	}

	return resultdoc.JobEventSummaryForReport{
		JobIdentity:    in.Identity,
		Metadata:       in.Metadata,
		RunnerType:     in.RunnerType,
		StartedAt:      in.StartedAt.UTC(),
		GeneratedAt:    in.GeneratedAt.UTC(),
		FinalizeReason: in.FinalizeReason,
		RulesSummary: resultdoc.RulesSummary{
			RuleCount:     len(in.ResolvedRules.Rules),
			WarningsCount: len(in.ResolvedRules.Warnings),
		},
		ResultSummary: resultdoc.ResultSummary{
			Result:    result,
			HitsCount: len(hits),
		},
		NetworkConnections: networkConnections(in.Snapshot.ObservationNetwork.Records),
		DomainObservations: domainObservations(in.Snapshot.ObservationDomain.Records),
		Hits:               hits,
	}
}

type ruleDetail struct {
	name      string
	ruleType  string
	condition string
}

func resultRuleType(ruleType string) string {
	if ruleType == "" {
		return "event"
	}
	return ruleType
}

func domainObservations(records []observations.DomainObservationRecord) []resultdoc.DomainObservation {
	out := make([]resultdoc.DomainObservation, 0, len(records))
	for _, record := range records {
		out = append(out, resultdoc.DomainObservation{
			Domain:               record.Domain,
			Processes:            observationProcessSummaries(record.Processes),
			ProcessOverflowCount: record.ProcessOverflowCount,
		})
	}
	return out
}

func networkConnections(records []observations.NetworkObservationRecord) []resultdoc.NetworkConnection {
	out := make([]resultdoc.NetworkConnection, 0, len(records))
	for _, record := range records {
		out = append(out, resultdoc.NetworkConnection{
			RemoteIP:             record.RemoteIP,
			RemotePort:           record.RemotePort,
			Protocol:             record.Protocol,
			Processes:            observationProcessSummaries(record.Processes),
			ProcessOverflowCount: record.ProcessOverflowCount,
		})
	}
	return out
}

func observationProcessSummaries(processes []observations.ProcessContext) []resultdoc.ObservationProcess {
	out := make([]resultdoc.ObservationProcess, 0, len(processes))
	for _, process := range processes {
		out = append(out, observationProcessSummary(process))
	}
	return out
}

func observationProcessSummary(process observations.ProcessContext) resultdoc.ObservationProcess {
	out := resultdoc.ObservationProcess{
		PID:           process.PID,
		StartBoottime: process.StartBoottime,
		ExecPath:      process.ExecPath,
	}
	if len(process.Ancestors) > 0 {
		out.Ancestors = make([]resultdoc.ObservationAncestorProcess, 0, len(process.Ancestors))
		for _, ancestor := range process.Ancestors {
			out.Ancestors = append(out.Ancestors, resultdoc.ObservationAncestorProcess{
				ExecPath: ancestor.ExecPath,
			})
		}
	}
	return out
}

func resultProcessSummary(process jobevent.ProcessSummary) resultdoc.ProcessSummary {
	out := resultdoc.ProcessSummary{
		PID:           process.PID,
		StartBoottime: process.StartBoottime,
		ExecPath:      process.ExecPath,
		Argv:          process.Argv,
	}
	if len(process.Ancestors) > 0 {
		out.Ancestors = make([]resultdoc.AncestorProcess, 0, len(process.Ancestors))
		for _, ancestor := range process.Ancestors {
			out.Ancestors = append(out.Ancestors, resultdoc.AncestorProcess{
				ExecPath: ancestor.ExecPath,
				Argv:     ancestor.Argv,
			})
		}
	}
	return out
}
