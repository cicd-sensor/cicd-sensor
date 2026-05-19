package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

type jobIdentityFlags struct {
	Provider               string
	ProviderHost           string
	ProjectPath            string
	GitHubRunID            string
	GitHubRunAttempt       string
	GitHubJob              string
	GitHubRunnerTrackingID string
	GitLabJobID            string
}

type jobMetadataFlags struct {
	CommitSHA   string
	Branch      string
	Trigger     string
	Workflow    string
	WorkflowRef string
	WorkflowSHA string
	Actor       string
}

func registerJobIdentityFlags(fs *flag.FlagSet, identity *jobIdentityFlags) {
	fs.StringVar(&identity.Provider, "provider", "", "CI provider (github or gitlab).")
	fs.StringVar(&identity.ProviderHost, "provider-host", "", "Normalized CI provider host.")
	fs.StringVar(&identity.ProjectPath, "project-path", "", "Provider project path (e.g. acme/example).")
	fs.StringVar(&identity.GitHubRunID, "github-run-id", "", "GitHub Actions run ID.")
	fs.StringVar(&identity.GitHubRunAttempt, "github-run-attempt", "", "GitHub Actions run attempt.")
	fs.StringVar(&identity.GitHubJob, "github-job", "", "GitHub Actions job name.")
	fs.StringVar(&identity.GitHubRunnerTrackingID, "github-runner-tracking-id", "", "GitHub runner tracking ID.")
	fs.StringVar(&identity.GitLabJobID, "gitlab-job-id", "", "GitLab CI job ID.")
}

func registerJobMetadataFlags(fs *flag.FlagSet, metadata *jobMetadataFlags) {
	fs.StringVar(&metadata.CommitSHA, "commit-sha", "", "Commit SHA associated with this job.")
	fs.StringVar(&metadata.Branch, "branch", "", "Branch or ref name associated with this job.")
	fs.StringVar(&metadata.Trigger, "trigger", "", "CI event or trigger name associated with this job.")
	fs.StringVar(&metadata.Workflow, "workflow", "", "Workflow name associated with this job.")
	fs.StringVar(&metadata.WorkflowRef, "workflow-ref", "", "Workflow file ref associated with this job.")
	fs.StringVar(&metadata.WorkflowSHA, "workflow-sha", "", "Workflow file commit SHA associated with this job.")
	fs.StringVar(&metadata.Actor, "actor", "", "User or actor that triggered this job.")
}

func printGitHubIdentityEnvHelp(w io.Writer) {
	fmt.Fprintln(w, "GitHub environment (used by default; flags override):")
	fmt.Fprintln(w, "  GITHUB_SERVER_URL")
	fmt.Fprintln(w, "        Provider host. Defaults to github.com when unset.")
	fmt.Fprintln(w, "  GITHUB_REPOSITORY")
	fmt.Fprintln(w, "        Provider project path, e.g. acme/example.")
	fmt.Fprintln(w, "  GITHUB_RUN_ID")
	fmt.Fprintln(w, "        GitHub Actions run ID.")
	fmt.Fprintln(w, "  GITHUB_RUN_ATTEMPT")
	fmt.Fprintln(w, "        GitHub Actions run attempt.")
	fmt.Fprintln(w, "  GITHUB_JOB")
	fmt.Fprintln(w, "        GitHub Actions job name.")
	fmt.Fprintln(w, "  RUNNER_TRACKING_ID")
	fmt.Fprintln(w, "        GitHub runner tracking ID.")
}

func printGitHubMetadataEnvHelp(w io.Writer) {
	fmt.Fprintln(w, "GitHub metadata environment (used by host start; flags override):")
	fmt.Fprintln(w, "  GITHUB_SHA, GITHUB_REF_NAME, GITHUB_EVENT_NAME")
	fmt.Fprintln(w, "  GITHUB_WORKFLOW, GITHUB_WORKFLOW_REF, GITHUB_WORKFLOW_SHA")
	fmt.Fprintln(w, "  GITHUB_ACTOR")
}

func applyGitHubEnvFallback(identity *jobIdentityFlags) {
	if identity.Provider == "" {
		identity.Provider = "github"
	}
	if identity.ProviderHost == "" {
		identity.ProviderHost = normalizeProviderHostFromServerURL(os.Getenv("GITHUB_SERVER_URL"))
	}
	if identity.ProjectPath == "" {
		identity.ProjectPath = os.Getenv("GITHUB_REPOSITORY")
	}
	if identity.GitHubRunID == "" {
		identity.GitHubRunID = os.Getenv("GITHUB_RUN_ID")
	}
	if identity.GitHubRunAttempt == "" {
		identity.GitHubRunAttempt = os.Getenv("GITHUB_RUN_ATTEMPT")
	}
	if identity.GitHubJob == "" {
		identity.GitHubJob = os.Getenv("GITHUB_JOB")
	}
	if identity.GitHubRunnerTrackingID == "" {
		identity.GitHubRunnerTrackingID = os.Getenv("RUNNER_TRACKING_ID")
	}
}

func applyGitHubMetadataEnvFallback(metadata *jobMetadataFlags) {
	if metadata.CommitSHA == "" {
		metadata.CommitSHA = os.Getenv("GITHUB_SHA")
	}
	if metadata.Branch == "" {
		metadata.Branch = os.Getenv("GITHUB_REF_NAME")
	}
	if metadata.Trigger == "" {
		metadata.Trigger = os.Getenv("GITHUB_EVENT_NAME")
	}
	if metadata.Workflow == "" {
		metadata.Workflow = os.Getenv("GITHUB_WORKFLOW")
	}
	if metadata.WorkflowRef == "" {
		metadata.WorkflowRef = os.Getenv("GITHUB_WORKFLOW_REF")
	}
	if metadata.WorkflowSHA == "" {
		metadata.WorkflowSHA = os.Getenv("GITHUB_WORKFLOW_SHA")
	}
	if metadata.Actor == "" {
		metadata.Actor = os.Getenv("GITHUB_ACTOR")
	}
}

func normalizeProviderHostFromServerURL(serverURL string) string {
	if serverURL == "" {
		serverURL = "https://github.com"
	}
	host := strings.TrimPrefix(serverURL, "http://")
	host = strings.TrimPrefix(host, "https://")
	if slash := strings.IndexByte(host, '/'); slash >= 0 {
		host = host[:slash]
	}
	if colon := strings.IndexByte(host, ':'); colon >= 0 {
		host = host[:colon]
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func buildJobIdentityRequest(identity jobIdentityFlags) (map[string]string, error) {
	if identity.Provider == "" {
		return nil, fmt.Errorf("provider is required")
	}
	switch identity.Provider {
	case "github", "gitlab":
	default:
		return nil, fmt.Errorf("provider must be github or gitlab")
	}
	if identity.ProviderHost == "" {
		return nil, fmt.Errorf("provider-host is required")
	}
	if identity.ProjectPath == "" {
		return nil, fmt.Errorf("project-path is required")
	}

	req := map[string]string{
		"provider":      identity.Provider,
		"provider_host": identity.ProviderHost,
		"project_path":  identity.ProjectPath,
	}

	switch identity.Provider {
	case "github":
		if identity.GitHubRunID == "" {
			return nil, fmt.Errorf("github-run-id is required")
		}
		if identity.GitHubRunAttempt == "" {
			return nil, fmt.Errorf("github-run-attempt is required")
		}
		if identity.GitHubJob == "" {
			return nil, fmt.Errorf("github-job is required")
		}
		if identity.GitHubRunnerTrackingID == "" {
			return nil, fmt.Errorf("github-runner-tracking-id is required")
		}
		req["github_run_id"] = identity.GitHubRunID
		req["github_run_attempt"] = identity.GitHubRunAttempt
		req["github_job"] = identity.GitHubJob
		req["github_runner_tracking_id"] = identity.GitHubRunnerTrackingID
	case "gitlab":
		if identity.GitLabJobID == "" {
			return nil, fmt.Errorf("gitlab-job-id is required")
		}
		req["gitlab_job_id"] = identity.GitLabJobID
	}

	return req, nil
}

func buildJobMetadataRequest(metadata jobMetadataFlags) map[string]string {
	req := make(map[string]string)
	if metadata.CommitSHA != "" {
		req["commit_sha"] = metadata.CommitSHA
	}
	if metadata.Branch != "" {
		req["branch"] = metadata.Branch
	}
	if metadata.Trigger != "" {
		req["trigger"] = metadata.Trigger
	}
	if metadata.Workflow != "" {
		req["workflow"] = metadata.Workflow
	}
	if metadata.WorkflowRef != "" {
		req["workflow_ref"] = metadata.WorkflowRef
	}
	if metadata.WorkflowSHA != "" {
		req["workflow_sha"] = metadata.WorkflowSHA
	}
	if metadata.Actor != "" {
		req["actor"] = metadata.Actor
	}
	return req
}

func addJobMetadataRequest(req map[string]any, metadata jobMetadataFlags) {
	metadataReq := buildJobMetadataRequest(metadata)
	if len(metadataReq) > 0 {
		req["metadata"] = metadataReq
	}
}

func requireGitHubProvider(identity jobIdentityFlags, unsupportedProviderMessage string) error {
	if identity.Provider != "github" {
		return fmt.Errorf("%s", unsupportedProviderMessage)
	}
	return nil
}
