package job_test

import (
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestJob_Lifecycle(t *testing.T) {
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}
	eventCh := make(chan jobevent.EventRecord, externalTestEventChannelSize)
	j := job.NewJob(externalTestLogger, id, meta, "machine", eventCh)

	if j.State() != job.JobStateRunning {
		t.Fatalf("initial state: got %q", j.State())
	}
	if j.Identity() != id {
		t.Fatalf("identity: got %#v, want %#v", j.Identity(), id)
	}
	if j.Metadata() != meta {
		t.Fatalf("metadata: got %#v, want %#v", j.Metadata(), meta)
	}
	if !j.StartedAt().Equal(j.StartedAt().UTC()) {
		t.Fatalf("started_at should be UTC: %s", j.StartedAt())
	}
	if !j.DeadlineAt().Equal(j.DeadlineAt().UTC()) {
		t.Fatalf("deadline_at should be UTC: %s", j.DeadlineAt())
	}

	j.MarkClosing()
	close(eventCh)
	<-j.Done()
	if j.State() != job.JobStateClosing {
		t.Fatalf("after finalize: got %q", j.State())
	}
}

func TestJob_FinalizeIdempotent(t *testing.T) {
	eventCh := make(chan jobevent.EventRecord, externalTestEventChannelSize)
	j := job.NewJob(externalTestLogger, jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"), jobcontext.JobMetadata{}, "machine", eventCh)

	j.MarkClosing()
	close(eventCh)
	<-j.Done()
	if j.State() != job.JobStateClosing {
		t.Fatalf("after first finalize: got %q", j.State())
	}

	// Second finalize is a no-op; state stays closing.
	j.MarkClosing()
	if j.State() != job.JobStateClosing {
		t.Fatalf("after second finalize: got %q", j.State())
	}
}

func TestJob_NilEventChannelIsImmediatelyDone(t *testing.T) {
	j := job.NewJob(externalTestLogger, jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"), jobcontext.JobMetadata{}, "machine", nil)

	select {
	case <-j.Done():
	case <-time.After(time.Second):
		t.Fatal("nil event channel job should be done immediately")
	}
	if j.State() != job.JobStateRunning {
		t.Fatalf("state: got %q, want running", j.State())
	}
}

func TestJob_NilLoggerUsesDefaultLogger(t *testing.T) {
	j := job.NewJob(nil, jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"), jobcontext.JobMetadata{}, "machine", nil)

	select {
	case <-j.Done():
	case <-time.After(time.Second):
		t.Fatal("nil logger job should still finish without an event worker")
	}
	if j.State() != job.JobStateRunning {
		t.Fatalf("state: got %q, want running", j.State())
	}
}

func TestJob_IsExpired(t *testing.T) {
	j := job.NewJob(externalTestLogger, jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"), jobcontext.JobMetadata{}, "machine", nil)
	if j.IsExpired() {
		t.Fatal("new job should not be expired")
	}

	j.SetDeadlineAtForTesting(time.Now().Add(-time.Second))
	if !j.IsExpired() {
		t.Fatal("job should be expired after deadline rewind")
	}
}

func TestJob_SetProjectScope_ResolvesScopeRules(t *testing.T) {
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}
	j := job.NewJob(externalTestLogger, id, meta, "machine", make(chan jobevent.EventRecord, externalTestEventChannelSize))

	scope := &jobscope.JobScopeState{
		Type: jobcontext.ScopeTypeProject,
		RuleSets: []rule.RuleSet{
			{
				RulesetID: "project-set",
				Rules: []rule.Rule{
					{
						RuleID:    "r1",
						EventType: jobevent.ProcessExec,
						Condition: `process_name == "bash"`,
						Action:    rule.RuleActionDetect,
					},
				},
			},
		},
	}
	scope.ResolveRules(jobcontext.JobIdentity{})

	if err := j.SetProjectScope(externalTestCtx, scope); err != nil {
		t.Fatalf("SetProjectScope: %v", err)
	}

	gotScope := j.ProjectScope()
	if gotScope == nil {
		t.Fatal("expected project scope to be set")
	}
	if len(gotScope.ResolvedRules.Rules) != 1 {
		t.Fatalf("resolved rules: got %d, want 1", len(gotScope.ResolvedRules.Rules))
	}

	if gotScope.ResolvedRules.Rules[0].CanonicalRuleID != "project-set/r1" {
		t.Fatalf("canonical rule ID: got %q, want %q", gotScope.ResolvedRules.Rules[0].CanonicalRuleID, "project-set/r1")
	}
}
