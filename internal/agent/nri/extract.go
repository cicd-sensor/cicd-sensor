package nri

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

const (
	githubIdentityAnnotation = "cicd-sensor.github.io/identity"
	githubMetadataAnnotation = "cicd-sensor.github.io/metadata"

	gitlabProjectNameLabel      = "project.runner.gitlab.com/name"
	gitlabProjectNamespaceLabel = "project.runner.gitlab.com/namespace"
	gitlabJobIDAnnotation       = "job.runner.gitlab.com/id"
	gitlabJobNameAnnotation     = "job.runner.gitlab.com/name"
	gitlabJobRefAnnotation      = "job.runner.gitlab.com/ref"
	gitlabJobSHAAnnotation      = "job.runner.gitlab.com/sha"
	gitlabJobURLAnnotation      = "job.runner.gitlab.com/url"
)

type stagingDecision struct {
	Provider   jobcontext.Provider
	Status     string
	SkipReason string
	Basename   string
	Identity   jobcontext.JobIdentity
	Metadata   jobcontext.JobMetadata
}

func stagingDecisionForCreateContainer(provider jobcontext.Provider, event CreateContainerEvent) (stagingDecision, bool) {
	if event.CgroupBasename == "" {
		return stagingDecision{Status: "skip", SkipReason: "cgroup_basename_missing"}, false
	}

	var decision stagingDecision
	var ok bool
	switch provider {
	case jobcontext.ProviderGitHub:
		decision, ok = githubStagingDecision(event)
	case jobcontext.ProviderGitLab:
		decision, ok = gitlabStagingDecision(event)
	default:
		return stagingDecision{Status: "skip", SkipReason: "provider_unsupported"}, false
	}
	if ok {
		decision.Basename = event.CgroupBasename
		return decision, true
	}
	if decision.SkipReason != "" {
		return decision, false
	}

	return stagingDecision{Status: "skip", SkipReason: "identity_missing"}, false
}

func githubStagingDecision(event CreateContainerEvent) (stagingDecision, bool) {
	rawIdentity := strings.TrimSpace(event.Pod.Annotations[githubIdentityAnnotation])
	if rawIdentity == "" {
		return stagingDecision{}, false
	}

	var identity jobcontext.JobIdentity
	if err := json.Unmarshal([]byte(rawIdentity), &identity); err != nil {
		return stagingDecision{Provider: jobcontext.ProviderGitHub, Status: "skip", SkipReason: "github_identity_malformed"}, false
	}
	if identity.Provider != jobcontext.ProviderGitHub {
		return stagingDecision{Provider: jobcontext.ProviderGitHub, Status: "skip", SkipReason: "github_identity_provider_mismatch"}, false
	}
	if err := identity.Validate(); err != nil {
		return stagingDecision{Provider: jobcontext.ProviderGitHub, Status: "skip", SkipReason: "github_identity_invalid"}, false
	}

	var metadata jobcontext.JobMetadata
	rawMetadata := strings.TrimSpace(event.Pod.Annotations[githubMetadataAnnotation])
	if rawMetadata != "" {
		if err := json.Unmarshal([]byte(rawMetadata), &metadata); err != nil {
			return stagingDecision{Provider: jobcontext.ProviderGitHub, Status: "skip", SkipReason: "github_metadata_malformed"}, false
		}
	}

	return stagingDecision{
		Provider: jobcontext.ProviderGitHub,
		Status:   "stage",
		Identity: identity,
		Metadata: metadata,
	}, true
}

func gitlabStagingDecision(event CreateContainerEvent) (stagingDecision, bool) {
	if shouldSkipGitLabContainer(event.Container.Name) {
		return stagingDecision{Provider: jobcontext.ProviderGitLab, Status: "skip", SkipReason: "gitlab_runtime_container"}, false
	}
	jobID := strings.TrimSpace(event.Pod.Annotations[gitlabJobIDAnnotation])
	if jobID == "" {
		return stagingDecision{}, false
	}
	urlHost, urlProjectPath, urlJobID := gitlabJobURLIdentity(event.Pod.Annotations[gitlabJobURLAnnotation])
	if urlJobID != "" && urlJobID != jobID {
		return stagingDecision{Provider: jobcontext.ProviderGitLab, Status: "skip", SkipReason: "gitlab_job_url_id_mismatch"}, false
	}
	projectPath := urlProjectPath
	if projectPath == "" {
		projectPath = gitlabProjectPath(event.Pod.Labels, envMap(event.Container.Env))
	}
	if projectPath == "" {
		return stagingDecision{Provider: jobcontext.ProviderGitLab, Status: "skip", SkipReason: "gitlab_project_path_missing"}, false
	}
	providerHost := urlHost
	if providerHost == "" {
		providerHost = gitlabProviderHost(event.Container.Env)
	}
	if providerHost == "" {
		return stagingDecision{Provider: jobcontext.ProviderGitLab, Status: "skip", SkipReason: "gitlab_provider_host_missing"}, false
	}

	identity := jobcontext.GitLabJobIdentity(providerHost, projectPath, jobID)
	if err := identity.Validate(); err != nil {
		return stagingDecision{Provider: jobcontext.ProviderGitLab, Status: "skip", SkipReason: "gitlab_identity_invalid"}, false
	}

	return stagingDecision{
		Provider: jobcontext.ProviderGitLab,
		Status:   "stage",
		Identity: identity,
		Metadata: gitlabMetadata(event),
	}, true
}

func shouldSkipGitLabContainer(name string) bool {
	switch name {
	case "helper", "init-permissions":
		return true
	default:
		return false
	}
}

// gitlabJobURLIdentity derives the provider host and project path from the
// runner-set job URL annotation (https://<host>/<project_path>/-/jobs/<id>).
// It is the preferred identity source: Pod label values cannot contain "/",
// so labels cannot represent nested group paths, and container env can be
// overridden by job configuration. A URL without the /-/jobs/ marker still
// yields the host; the caller falls back for the project path.
func gitlabJobURLIdentity(rawURL string) (host, projectPath, jobID string) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", "", ""
	}
	host, err := jobcontext.DeriveProviderHost(rawURL)
	if err != nil {
		return "", "", ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", "", ""
	}
	path, rest, found := strings.Cut(parsed.Path, "/-/jobs/")
	if !found {
		return host, "", ""
	}
	jobID, _, _ = strings.Cut(strings.Trim(rest, "/"), "/")
	return host, strings.Trim(path, "/"), strings.TrimSpace(jobID)
}

// gitlabProjectPath is the fallback when the job URL annotation is missing.
// Label values cannot contain "/", so the label-derived path is wrong for
// projects under nested groups; CI_PROJECT_PATH is job-author-influenced.
func gitlabProjectPath(labels map[string]string, env map[string]string) string {
	namespace := strings.Trim(strings.TrimSpace(labels[gitlabProjectNamespaceLabel]), "/")
	name := strings.Trim(strings.TrimSpace(labels[gitlabProjectNameLabel]), "/")
	if namespace != "" && name != "" {
		return namespace + "/" + name
	}
	return strings.Trim(strings.TrimSpace(env["CI_PROJECT_PATH"]), "/")
}

func gitlabProviderHost(env []string) string {
	values := envMap(env)
	if host := strings.TrimSpace(values["CI_SERVER_HOST"]); host != "" {
		return strings.ToLower(strings.TrimRight(host, "."))
	}
	if rawURL := strings.TrimSpace(values["CI_SERVER_URL"]); rawURL != "" {
		host, err := jobcontext.DeriveProviderHost(rawURL)
		if err == nil {
			return host
		}
	}
	return ""
}

func gitlabMetadata(event CreateContainerEvent) jobcontext.JobMetadata {
	env := envMap(event.Container.Env)
	return jobcontext.JobMetadata{
		CommitSHA:          firstNonEmpty(event.Pod.Annotations[gitlabJobSHAAnnotation], env["CI_COMMIT_SHA"]),
		RefName:            firstNonEmpty(event.Pod.Annotations[gitlabJobRefAnnotation], env["CI_COMMIT_REF_NAME"]),
		Trigger:            env["CI_PIPELINE_SOURCE"],
		ActorID:            env["GITLAB_USER_ID"],
		ActorName:          firstNonEmpty(env["GITLAB_USER_LOGIN"], env["GITLAB_USER_NAME"]),
		GitLabJobName:      firstNonEmpty(event.Pod.Annotations[gitlabJobNameAnnotation], env["CI_JOB_NAME"]),
		GitLabConfigRefURI: env["CI_CONFIG_PATH"],
	}
}

func envMap(env []string) map[string]string {
	values := make(map[string]string, len(env))
	for _, kv := range env {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || key == "" {
			continue
		}
		if _, exists := values[key]; exists {
			continue
		}
		values[key] = value
	}
	return values
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func (d stagingDecision) String() string {
	if d.SkipReason != "" {
		return fmt.Sprintf("%s:%s", d.Status, d.SkipReason)
	}
	return d.Status
}
