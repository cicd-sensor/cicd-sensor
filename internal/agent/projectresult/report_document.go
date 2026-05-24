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
			name:        resolved.Rule.RuleName,
			description: resolved.Rule.Description,
			ruleType:    resultRuleType(resolved.Rule.Type),
			condition:   resolved.Rule.Condition,
			tags:        resolved.Rule.Tags,
		}
	}

	result := observations.OverallResult(in.Snapshot.Hits)
	hits := make([]resultdoc.HitRecord, 0, len(in.Snapshot.Hits))
	for _, hit := range in.Snapshot.Hits {
		detail := ruleDetails[hit.Identity]
		events := make([]resultdoc.AlertEvent, 0, len(hit.AlertEventRecords))
		for _, event := range hit.AlertEventRecords {
			process := resultProcessSummary(jobevent.RedactProcessSummaryForOutput(event.Process))
			events = append(events, resultdoc.AlertEvent{
				Timestamp: event.Timestamp,
				EventType: event.EventType,
				Process:   &process,
				Payload:   event.Payload,
			})
		}
		hits = append(hits, resultdoc.HitRecord{
			RulesetID:       hit.RulesetID,
			RuleID:          hit.RuleID,
			RulesetRevision: hit.RulesetRevision,
			RuleName:        detail.name,
			RuleDescription: detail.description,
			RuleType:        detail.ruleType,
			RuleCondition:   detail.condition,
			RuleTags:        detail.tags,
			Action:          hit.Action,
			HitCount:        hit.HitCount,
			MaxAlerts:       hit.MaxAlerts,
			AlertEvents:     events,
		})
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
			Result: result,
		},
		NetworkConnections: networkConnections(in.Snapshot.ObservationNetwork.Records),
		DomainObservations: domainObservations(in.Snapshot.ObservationDomain.Records),
		Hits:               hits,
	}
}

type ruleDetail struct {
	name        string
	description string
	ruleType    string
	condition   string
	tags        map[string]string
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
