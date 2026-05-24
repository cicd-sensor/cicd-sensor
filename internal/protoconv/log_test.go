package protoconv

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestToLogContext_GitHub(t *testing.T) {
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "25624771295", "build", "2", "runner-1")
	metadata := jobcontext.JobMetadata{
		CommitSHA:         "abc123",
		RefName:           "main",
		Trigger:           "push",
		ActorID:           "1001",
		ActorName:         "octocat",
		GitHubWorkflowRef: "acme/example/.github/workflows/ci.yml@refs/heads/main",
		GitHubWorkflowSHA: "def456",
		GitHubWorkflow:    "CI",
	}

	got := ToLogContext(identity, metadata)
	if got.Provider != "github" ||
		got.ProviderHost != "github.com" ||
		got.ProjectPath != "acme/example" ||
		got.JobLink != "https://github.com/acme/example/actions/runs/25624771295" ||
		got.GithubRunId != "25624771295" ||
		got.GithubJob != "build" ||
		got.GithubRunAttempt != "2" ||
		got.GithubRunnerTrackingId != "runner-1" ||
		got.CommitSha != "abc123" ||
		got.RefName != "main" ||
		got.Trigger != "push" ||
		got.ActorId != "1001" ||
		got.ActorName != "octocat" ||
		got.GithubWorkflowRef != metadata.GitHubWorkflowRef ||
		got.GithubWorkflowSha != "def456" ||
		got.GithubWorkflow != "CI" {
		t.Fatalf("github log job context mismatch: %+v", got)
	}
}

// JSON marshal output must not leak gitlab_* keys into a GitHub job log.
func TestToLogContext_GitHubJSONOmitsGitLabFields(t *testing.T) {
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "25624771295", "build", "2", "runner-1")
	ctx := ToLogContext(identity, jobcontext.JobMetadata{CommitSHA: "abc"})
	data, err := (protojson.MarshalOptions{EmitDefaultValues: false}).Marshal(ctx)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"gitlab_job_id", "gitlab_job_name", "gitlab_config_ref_uri"} {
		if _, present := raw[key]; present {
			t.Errorf("github job log should omit %q, but it was present: %s", key, data)
		}
	}
}

func TestToLogContext_GitLab(t *testing.T) {
	identity := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "14274377073")
	metadata := jobcontext.JobMetadata{
		CommitSHA:          "abc",
		RefName:            "main",
		Trigger:            "push",
		ActorID:            "7393749",
		ActorName:          "rung",
		GitLabJobName:      "jirojiro-smoke",
		GitLabConfigRefURI: "gitlab.com/group/project//.gitlab-ci.yml@refs/heads/main",
	}
	got := ToLogContext(identity, metadata)
	if got.Provider != "gitlab" ||
		got.GitlabJobId != "14274377073" ||
		got.GitlabJobName != "jirojiro-smoke" ||
		got.GitlabConfigRefUri != metadata.GitLabConfigRefURI ||
		got.ActorId != "7393749" ||
		got.ActorName != "rung" {
		t.Fatalf("gitlab log job context mismatch: %+v", got)
	}
}

// JSON marshal output must not leak github_* keys into a GitLab job log.
func TestToLogContext_GitLabJSONOmitsGitHubFields(t *testing.T) {
	identity := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "14274377073")
	ctx := ToLogContext(identity, jobcontext.JobMetadata{CommitSHA: "abc"})
	data, err := (protojson.MarshalOptions{EmitDefaultValues: false}).Marshal(ctx)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"github_run_id", "github_job", "github_run_attempt", "github_runner_tracking_id", "github_workflow_ref", "github_workflow_sha", "github_workflow"} {
		if _, present := raw[key]; present {
			t.Errorf("gitlab job log should omit %q, but it was present: %s", key, data)
		}
	}
}

func TestToLogContext_EmptyJobLink(t *testing.T) {
	tests := []struct {
		name     string
		identity jobcontext.JobIdentity
	}{
		{
			name: "github missing run id",
			identity: jobcontext.GitHubJobIdentity(
				"github.com",
				"acme/example",
				"",
				"build",
				"1",
				"runner-1",
			),
		},
		{
			name:     "gitlab missing job id",
			identity: jobcontext.GitLabJobIdentity("gitlab.com", "group/project", ""),
		},
		{
			name: "missing provider host",
			identity: jobcontext.JobIdentity{
				Provider:    jobcontext.ProviderGitHub,
				ProjectPath: "acme/example",
				GitHubRunID: "123",
			},
		},
		{
			name: "missing project path",
			identity: jobcontext.JobIdentity{
				Provider:     jobcontext.ProviderGitHub,
				ProviderHost: "github.com",
				GitHubRunID:  "123",
			},
		},
		{
			name: "unknown provider",
			identity: jobcontext.JobIdentity{
				Provider:     jobcontext.Provider("other"),
				ProviderHost: "example.com",
				ProjectPath:  "acme/example",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToLogContext(tt.identity, jobcontext.JobMetadata{}).JobLink; got != "" {
				t.Fatalf("job link: got %q, want empty", got)
			}
		})
	}
}
