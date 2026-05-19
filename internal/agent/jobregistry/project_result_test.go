package jobregistry_test

import (
	"encoding/json"
	"errors"
	"testing"

	jobpkg "github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
)

func TestJobRegistry_RequestGitHubProjectResult_ExistingJob(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	if _, err := jr.ApplyGitHubProjectStart(testCtx, id, meta, "machine", 0, 0, nil, managerclient.Connection{}, nil, false); err != nil {
		t.Fatalf("apply project start: %v", err)
	}

	body, err := jr.RequestGitHubProjectResult(testCtx, id, 0)
	if err != nil {
		t.Fatalf("request project result: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("result body is empty")
	}
	if !json.Valid(body) {
		t.Fatal("result body is not valid JSON")
	}
	var entry resultdoc.JobEventSummaryForReport
	if err := json.Unmarshal(body, &entry); err != nil {
		t.Fatalf("unmarshal job_result_log: %v", err)
	}
	if entry.JobIdentity != id {
		t.Fatalf("job_identity: got %#v, want %#v", entry.JobIdentity, id)
	}
}

func TestJobRegistry_RequestGitHubProjectResult_MissingJob(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "missing")

	_, err := jr.RequestGitHubProjectResult(testCtx, id, 0)
	if !errors.Is(err, jobregistry.ErrJobNotFound) {
		t.Fatalf("request project result error: got %v, want %v", err, jobregistry.ErrJobNotFound)
	}
}

func TestJobRegistry_RequestGitHubProjectResult_ProjectScopeMissing(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	if _, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", 0, managerclient.Connection{}, staticManagerFetcher{}, false); err != nil {
		t.Fatalf("apply host start: %v", err)
	}
	_, err := jr.RequestGitHubProjectResult(testCtx, id, 0)
	if !errors.Is(err, jobpkg.ErrProjectScopeMissing) {
		t.Fatalf("request project result error: got %v, want %v", err, jobpkg.ErrProjectScopeMissing)
	}
}
