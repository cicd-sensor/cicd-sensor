package protoconv

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestToJobLogContext_GitHub(t *testing.T) {
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "25624771295", "build", "2", "runner-1")
	metadata := jobcontext.JobMetadata{
		CommitSHA:   "abc123",
		Branch:      "main",
		Trigger:     "push",
		Workflow:    "CI",
		WorkflowRef: "acme/example/.github/workflows/ci.yml@refs/heads/main",
		WorkflowSHA: "def456",
		Actor:       "octocat",
	}

	got := ToJobLogContext(identity, metadata, "github-hosted")
	if got.Provider != "github" ||
		got.ProviderHost != "github.com" ||
		got.ProjectPath != "acme/example" ||
		got.JobLink != "https://github.com/acme/example/actions/runs/25624771295" ||
		got.GithubRunId != "25624771295" ||
		got.GithubJob != "build" ||
		got.GithubRunAttempt != "2" ||
		got.GithubRunnerTrackingId != "runner-1" ||
		got.RunnerKind != "github-hosted" ||
		got.CommitSha != "abc123" ||
		got.RefName != "main" ||
		got.Trigger != "push" ||
		got.WorkflowName != "CI" ||
		got.GithubWorkflowRef != metadata.WorkflowRef ||
		got.GithubWorkflowSha != "def456" ||
		got.Actor != "octocat" {
		t.Fatalf("github log job context mismatch: %+v", got)
	}
}

func TestToJobLogContext_GitLab(t *testing.T) {
	got := ToJobLogContext(
		jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "14274377073"),
		jobcontext.JobMetadata{},
		"gitlab-container",
	)
	if got.Provider != "gitlab" ||
		got.ProviderHost != "gitlab.com" ||
		got.ProjectPath != "group/project" ||
		got.JobLink != "https://gitlab.com/group/project/-/jobs/14274377073" ||
		got.GitlabJobId != "14274377073" ||
		got.RunnerKind != "gitlab-container" {
		t.Fatalf("gitlab log job context mismatch: %+v", got)
	}
}

func TestToJobLogContext_EmptyJobLink(t *testing.T) {
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
			if got := ToJobLogContext(tt.identity, jobcontext.JobMetadata{}, "").JobLink; got != "" {
				t.Fatalf("job link: got %q, want empty", got)
			}
		})
	}
}
