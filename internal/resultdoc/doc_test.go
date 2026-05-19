package resultdoc_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
)

func TestJobEventSummaryForReport_KeepsRunnerKindOutsideMetadata(t *testing.T) {
	doc := resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
		Metadata: jobcontext.JobMetadata{
			CommitSHA: "abc123",
		},
		RunnerKind:     "machine",
		StartedAt:      time.Unix(0, 0).UTC(),
		GeneratedAt:    time.Unix(1, 0).UTC(),
		FinalizeReason: "shutdown",
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["job_identity"]; !ok {
		t.Fatal("job_identity missing")
	}
	if _, ok := raw["metadata"]; !ok {
		t.Fatal("metadata missing")
	}
	if got, ok := raw["runner_kind"]; !ok || got != "machine" {
		t.Fatalf("runner_kind: got %v, present=%v", got, ok)
	}
	metadata, ok := raw["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata shape: got %#v", raw["metadata"])
	}
	if _, ok := metadata["runner_kind"]; ok {
		t.Fatal("metadata.runner_kind should not be emitted")
	}
	if _, ok := raw["build_environment"]; ok {
		t.Fatal("build_environment should not be emitted")
	}
}
