package jobscope

import (
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/projectresult"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
)

type ReportInputs struct {
	Identity   jobcontext.JobIdentity
	Metadata   jobcontext.JobMetadata
	RunnerKind string
	StartedAt  time.Time
}

func (s *JobScopeState) BuildJobEventSummaryForReport(in ReportInputs, finalizeReason string, generatedAt time.Time) resultdoc.JobEventSummaryForReport {
	return projectresult.BuildJobEventSummaryForReport(projectresult.ReportDocumentInput{
		Identity:       in.Identity,
		Metadata:       in.Metadata,
		RunnerKind:     in.RunnerKind,
		StartedAt:      in.StartedAt,
		GeneratedAt:    generatedAt,
		FinalizeReason: finalizeReason,
		ResolvedRules:  s.ResolvedRules,
		Snapshot:       s.ObservationSnapshot(),
	})
}
