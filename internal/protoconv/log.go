package protoconv

import (
	"net/url"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
)

func ToJobLogContext(identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerKind string) *logv1.JobLogContext {
	return &logv1.JobLogContext{
		Provider:               string(identity.Provider),
		ProviderHost:           identity.ProviderHost,
		ProjectPath:            identity.ProjectPath,
		RunnerKind:             runnerKind,
		JobLink:                logJobLink(identity),
		CommitSha:              metadata.CommitSHA,
		RefName:                metadata.Branch,
		Trigger:                metadata.Trigger,
		WorkflowName:           metadata.Workflow,
		Actor:                  metadata.Actor,
		GithubRunId:            identity.GitHubRunID,
		GithubJob:              identity.GitHubJob,
		GithubRunAttempt:       identity.GitHubRunAttempt,
		GithubRunnerTrackingId: identity.GitHubRunnerTrackingID,
		GithubWorkflowRef:      metadata.WorkflowRef,
		GithubWorkflowSha:      metadata.WorkflowSHA,
		GitlabJobId:            identity.GitLabJobID,
	}
}

func logJobLink(identity jobcontext.JobIdentity) string {
	if identity.ProviderHost == "" || identity.ProjectPath == "" {
		return ""
	}
	u := url.URL{Scheme: "https", Host: identity.ProviderHost}
	switch identity.Provider {
	case jobcontext.ProviderGitHub:
		if identity.GitHubRunID == "" {
			return ""
		}
		u.Path = strings.TrimSuffix("/"+identity.ProjectPath, "/") + "/actions/runs/" + identity.GitHubRunID
	case jobcontext.ProviderGitLab:
		if identity.GitLabJobID == "" {
			return ""
		}
		u.Path = strings.TrimSuffix("/"+identity.ProjectPath, "/") + "/-/jobs/" + identity.GitLabJobID
	default:
		return ""
	}
	return u.String()
}
