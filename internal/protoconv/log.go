package protoconv

import (
	"net/url"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
)

// ToLogContext populates only provider-relevant fields so the unrelated
// provider's keys stay zero-valued and drop out of marshalled JSON.
func ToLogContext(identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata) *logv1.LogContext {
	out := &logv1.LogContext{
		Provider:     string(identity.Provider),
		ProviderHost: identity.ProviderHost,
		ProjectPath:  identity.ProjectPath,
		JobLink:      logJobLink(identity),
		CommitSha:    metadata.CommitSHA,
		RefName:      metadata.RefName,
		Trigger:      metadata.Trigger,
		ActorId:      metadata.ActorID,
		ActorName:    metadata.ActorName,
	}
	switch identity.Provider {
	case jobcontext.ProviderGitHub:
		out.GithubRunId = identity.GitHubRunID
		out.GithubJob = identity.GitHubJob
		out.GithubRunAttempt = identity.GitHubRunAttempt
		out.GithubRunnerTrackingId = identity.GitHubRunnerTrackingID
		out.GithubWorkflowRef = metadata.GitHubWorkflowRef
		out.GithubWorkflowSha = metadata.GitHubWorkflowSHA
		out.GithubWorkflow = metadata.GitHubWorkflow
	case jobcontext.ProviderGitLab:
		out.GitlabJobId = identity.GitLabJobID
		out.GitlabJobName = metadata.GitLabJobName
		out.GitlabConfigRefUri = metadata.GitLabConfigRefURI
	}
	return out
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
