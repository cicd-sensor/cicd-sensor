package jobcontext_test

import (
	"encoding/json"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestJobMetadata_OmitsEmptyOptionalFields(t *testing.T) {
	m := jobcontext.JobMetadata{}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{
		"commit_sha",
		"ref_name",
		"trigger",
		"actor_id",
		"actor_name",
		"github_workflow_ref",
		"github_workflow_sha",
		"github_workflow",
		"gitlab_job_name",
		"gitlab_config_ref_uri",
	} {
		if _, ok := raw[key]; ok {
			t.Errorf("expected key %q to be omitted, but it was present", key)
		}
	}
}

func TestJobMetadata_JSONRoundTrip(t *testing.T) {
	input := jobcontext.JobMetadata{
		CommitSHA:          "abc123",
		RefName:            "main",
		Trigger:            "push",
		ActorID:            "1001",
		ActorName:          "alice",
		GitHubWorkflowRef:  "acme/example/.github/workflows/build.yml@refs/heads/main",
		GitHubWorkflowSHA:  "def456",
		GitHubWorkflow:     "build.yml",
		GitLabJobName:      "jirojiro-smoke",
		GitLabConfigRefURI: "gitlab.com/acme/example//.gitlab-ci.yml@refs/heads/main",
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got jobcontext.JobMetadata
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != input {
		t.Fatalf("metadata: got %+v, want %+v", got, input)
	}
}

func TestJobMetadata_JSONFieldOrderMatchesLogContext(t *testing.T) {
	input := jobcontext.JobMetadata{
		CommitSHA:          "abc123",
		RefName:            "main",
		Trigger:            "push",
		ActorID:            "1001",
		ActorName:          "alice",
		GitHubWorkflowRef:  "acme/example/.github/workflows/build.yml@refs/heads/main",
		GitHubWorkflowSHA:  "def456",
		GitHubWorkflow:     "build.yml",
		GitLabJobName:      "jirojiro-smoke",
		GitLabConfigRefURI: "gitlab.com/acme/example//.gitlab-ci.yml@refs/heads/main",
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"commit_sha":"abc123","ref_name":"main","trigger":"push","actor_id":"1001","actor_name":"alice","github_workflow_ref":"acme/example/.github/workflows/build.yml@refs/heads/main","github_workflow_sha":"def456","github_workflow":"build.yml","gitlab_job_name":"jirojiro-smoke","gitlab_config_ref_uri":"gitlab.com/acme/example//.gitlab-ci.yml@refs/heads/main"}`
	if string(data) != want {
		t.Fatalf("json:\ngot  %s\nwant %s", data, want)
	}
}
