package jobregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// RequestGitHubProjectResult builds the GitHub project-scope report document.
func (jr *JobRegistry) RequestGitHubProjectResult(ctx context.Context, identity jobcontext.JobIdentity, peerPID int32) ([]byte, error) {
	j := jr.get(identity)
	if j == nil {
		return nil, ErrJobNotFound
	}
	if err := jr.verifyPeerPIDBelongsToJob(ctx, peerPID, identity); err != nil {
		return nil, err
	}
	projectScope := j.ProjectScope()
	if projectScope == nil {
		return nil, job.ErrProjectScopeMissing
	}
	logEntry := projectScope.BuildJobEventSummaryForReport(jobscope.ReportInputs{
		Identity:   j.Identity(),
		Metadata:   j.Metadata(),
		RunnerType: j.RunnerType(),
		StartedAt:  j.StartedAt(),
	}, "request", time.Now().UTC())
	body, err := json.MarshalIndent(logEntry, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal project result: %w", err)
	}
	body = append(body, '\n')
	if err := projectScope.CloseDebugOutput(ctx); err != nil {
		return nil, fmt.Errorf("close debug output before project result response: %w", err)
	}

	jr.logger.InfoContext(ctx, "github_project_result_generated",
		"job_identity", identity,
		"size_bytes", len(body),
	)

	return body, nil
}
