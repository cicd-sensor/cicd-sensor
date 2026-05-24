package protoconv

import (
	"net/url"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	attestationv1alpha1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/attestation/v1alpha1"
)

// ToAttestationJob builds the attestation v1alpha1 JobContext. Kept fully
// independent of log/v1's LogContext so the two wire schemas can evolve
// separately even though their field sets overlap today.
func ToAttestationJob(identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata) *attestationv1alpha1.JobContext {
	out := &attestationv1alpha1.JobContext{
		Provider:     string(identity.Provider),
		ProviderHost: identity.ProviderHost,
		ProjectPath:  identity.ProjectPath,
		JobLink:      attestationJobLink(identity),
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

func attestationJobLink(identity jobcontext.JobIdentity) string {
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
