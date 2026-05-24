package job

import (
	"errors"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestJob_EventWorkerProcessesReceivedEvent(t *testing.T) {
	t.Parallel()

	job, eventCh := newTestJob(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"), jobcontext.JobMetadata{}, testEventChannelSize)
	if err := job.SetHostScope(testCtx, jobscope.NewHost()); err != nil {
		t.Fatalf("SetHostScope: %v", err)
	}

	process := jobevent.ProcessSummary{
		PID:      100,
		ExecPath: "/usr/bin/curl",
	}
	connectEvent := jobevent.EventRecord{
		EventType: jobevent.NetworkConnect,
		Timestamp: time.Date(2026, 4, 16, 1, 2, 3, 4, time.UTC),
		Payload: map[string]any{
			"remote_ip":   "example.com",
			"remote_port": 443,
			"protocol":    "tcp",
		},
		Process: process,
	}
	domainEvent := jobevent.EventRecord{
		EventType: jobevent.Domain,
		Timestamp: time.Date(2026, 4, 16, 1, 2, 3, 5, time.UTC),
		Payload: map[string]any{
			"domain": "example.com",
			"source": "dns",
		},
		Process: process,
	}

	sendTestEvent(t, eventCh, connectEvent)
	sendTestEvent(t, eventCh, domainEvent)

	waitForJob(t, "worker should process both events before snapshot", func() bool {
		snapshot := job.HostScope().ObservationSnapshot()
		return snapshot.Counters.EventsTotal == 2 &&
			len(snapshot.ObservationDomain.Records) == 1 &&
			len(snapshot.ObservationNetwork.Records) == 1
	})

	finishTestJob(job, eventCh)

	snapshot := job.HostScope().ObservationSnapshot()
	if got := snapshot.Counters.EventsTotal; got != 2 {
		t.Fatalf("events_total: got %d, want 2", got)
	}
	if got := snapshot.Counters.EventsDropped; got != 0 {
		t.Fatalf("events_dropped: got %d, want 0", got)
	}
	wantDomain := "example.com"
	if got := snapshot.ObservationDomain.Records[0].Domain; got != wantDomain {
		t.Fatalf("domain record: got %#v, want %#v", got, wantDomain)
	}
	if got := snapshot.ObservationNetwork.Records[0].RemoteIP; got != "example.com" {
		t.Fatalf("network ip: got %q, want example.com", got)
	}
}

func TestJob_FinalizeDrainsQueuedEventsBeforeSnapshot(t *testing.T) {
	t.Parallel()

	job, eventCh := newTestJob(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"), jobcontext.JobMetadata{}, testEventChannelSize)
	if err := job.SetHostScope(testCtx, jobscope.NewHost()); err != nil {
		t.Fatalf("SetHostScope: %v", err)
	}

	sendTestEvent(t, eventCh, testDispatchEvent("/usr/bin/curl", "registry.npmjs.org", 443))
	sendTestEvent(t, eventCh, testDispatchEvent("/usr/bin/bash", "fulcio.sigstore.dev", 443))
	finishTestJob(job, eventCh)

	snapshot := job.HostScope().ObservationSnapshot()
	if got := len(snapshot.ObservationNetwork.Records); got != 2 {
		t.Fatalf("network records length after finalize: got %d, want 2", got)
	}
	if got := snapshot.Counters.EventsTotal; got != 2 {
		t.Fatalf("events_total after finalize: got %d, want 2", got)
	}
}

func TestJob_EventWorkerWithNoScopeDrainsEvent(t *testing.T) {
	t.Parallel()

	job, eventCh := newTestJob(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"), jobcontext.JobMetadata{}, testEventChannelSize)

	sendTestEvent(t, eventCh, testDispatchEvent("/usr/bin/curl", "registry.npmjs.org", 443))
	finishTestJob(job, eventCh)
}

func TestJob_SetProjectScopeConcurrentWithEventWorkerRemainsRaceFree(t *testing.T) {
	t.Parallel()

	job, eventCh := newTestJob(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"), jobcontext.JobMetadata{}, testEventChannelSize)

	done := make(chan struct{})
	go func() {
		defer close(done)
		scope := newProjectRuleScope("project-set", "project-rule", "a.example.com")
		if err := job.SetProjectScope(testCtx, scope); err != nil {
			t.Errorf("SetProjectScope: %v", err)
		}
	}()

	for i := 0; i < 250; i++ {
		host := "a.example.com"
		if i%2 == 1 {
			host = "b.example.com"
		}
		sendTestEvent(t, eventCh, testDispatchEvent("/usr/bin/curl", host, int64(443+i)))
	}
	<-done
	for i := 250; i < 300; i++ {
		host := "a.example.com"
		if i%2 == 1 {
			host = "b.example.com"
		}
		sendTestEvent(t, eventCh, testDispatchEvent("/usr/bin/curl", host, int64(443+i)))
	}
	finishTestJob(job, eventCh)

	projectScope := job.ProjectScope()
	if projectScope == nil {
		t.Fatal("expected project scope to remain set")
	}
	if projectScope.Observations == nil {
		t.Fatal("expected project scope observations to remain set")
	}
	counters := projectScope.ObservationSnapshot().Counters
	if counters.EventsTotal == 0 {
		t.Fatal("expected concurrent event worker attempts to be observed")
	}
}

func TestJob_SetHostScope_RejectsProjectScope(t *testing.T) {
	t.Parallel()

	job := newTestJobWithoutWorker(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"), jobcontext.JobMetadata{})

	err := job.SetHostScope(testCtx, jobscope.NewProject())
	if err == nil {
		t.Fatal("expected SetHostScope to reject a project scope")
	}
	if job.HostScope() != nil {
		t.Fatal("expected host scope to remain unset after type mismatch")
	}
	if !errors.Is(err, jobscope.ErrScopeTypeMismatch) {
		t.Fatalf("error: got %v, want %v", err, jobscope.ErrScopeTypeMismatch)
	}
}

func TestJob_SetHostScope_RejectsNilScope(t *testing.T) {
	t.Parallel()

	job := newTestJobWithoutWorker(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"), jobcontext.JobMetadata{})

	err := job.SetHostScope(testCtx, nil)
	if !errors.Is(err, ErrHostScopeRequired) {
		t.Fatalf("SetHostScope nil: got %v, want %v", err, ErrHostScopeRequired)
	}
	if job.HostScope() != nil {
		t.Fatal("nil host scope should not set host scope")
	}
}

func TestJob_SetProjectScope_RejectsHostScope(t *testing.T) {
	t.Parallel()

	job := newTestJobWithoutWorker(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"), jobcontext.JobMetadata{})

	err := job.SetProjectScope(testCtx, jobscope.NewHost())
	if err == nil {
		t.Fatal("expected SetProjectScope to reject a host scope")
	}
	if job.ProjectScope() != nil {
		t.Fatal("expected project scope to remain unset after type mismatch")
	}
	if !errors.Is(err, jobscope.ErrScopeTypeMismatch) {
		t.Fatalf("error: got %v, want %v", err, jobscope.ErrScopeTypeMismatch)
	}
}

func TestJob_SetProjectScope_RejectsNilScope(t *testing.T) {
	t.Parallel()

	job := newTestJobWithoutWorker(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"), jobcontext.JobMetadata{})

	err := job.SetProjectScope(testCtx, nil)
	if !errors.Is(err, ErrProjectScopeRequired) {
		t.Fatalf("SetProjectScope nil: got %v, want %v", err, ErrProjectScopeRequired)
	}
	if job.ProjectScope() != nil {
		t.Fatal("nil project scope should not set project scope")
	}
}

func TestJob_SetHostScope_RejectsDuplicate(t *testing.T) {
	t.Parallel()

	job := newTestJobWithoutWorker(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"), jobcontext.JobMetadata{})
	first := jobscope.NewHost()
	if err := job.SetHostScope(testCtx, first); err != nil {
		t.Fatalf("SetHostScope first: %v", err)
	}

	second := jobscope.NewHost()
	err := job.SetHostScope(testCtx, second)
	if !errors.Is(err, ErrHostScopeAlreadySet) {
		t.Fatalf("SetHostScope duplicate: got %v, want %v", err, ErrHostScopeAlreadySet)
	}
	if job.HostScope() != first {
		t.Fatal("duplicate host scope should not replace the original")
	}
}

func TestJob_SetProjectScope_RejectsDuplicate(t *testing.T) {
	t.Parallel()

	job := newTestJobWithoutWorker(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"), jobcontext.JobMetadata{})
	first := jobscope.NewProject()
	if err := job.SetProjectScope(testCtx, first); err != nil {
		t.Fatalf("SetProjectScope first: %v", err)
	}

	second := jobscope.NewProject()
	err := job.SetProjectScope(testCtx, second)
	if !errors.Is(err, ErrProjectScopeAlreadySet) {
		t.Fatalf("SetProjectScope duplicate: got %v, want %v", err, ErrProjectScopeAlreadySet)
	}
	if job.ProjectScope() != first {
		t.Fatal("duplicate project scope should not replace the original")
	}
}

func TestJob_SetScopeAfterClosingIsNoop(t *testing.T) {
	t.Parallel()

	job := newTestJobWithoutWorker(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"), jobcontext.JobMetadata{})
	host := jobscope.NewHost()
	if err := job.SetHostScope(testCtx, host); err != nil {
		t.Fatalf("SetHostScope first: %v", err)
	}

	job.MarkClosing()
	if err := job.SetHostScope(testCtx, jobscope.NewHost()); err != nil {
		t.Fatalf("SetHostScope after closing: %v", err)
	}
	if err := job.SetProjectScope(testCtx, jobscope.NewProject()); err != nil {
		t.Fatalf("SetProjectScope after closing: %v", err)
	}
	<-job.Done()

	if job.HostScope() != host {
		t.Fatal("closing scope attach should not replace existing host scope")
	}
	if job.ProjectScope() != nil {
		t.Fatal("closing scope attach should not add project scope")
	}
}

func newProjectRuleScope(setIdentity, ruleID, remoteHost string) *jobscope.JobScopeState {
	scope := jobscope.NewProject()
	scope.RuleSets = []rule.RuleSet{{
		RulesetID: setIdentity,
		Rules: []rule.Rule{{
			RuleID:    ruleID,
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "` + remoteHost + `"`,
			Action:    rule.RuleActionDetect,
		}},
	}}
	scope.ResolveRules(jobcontext.JobIdentity{})
	return scope
}

func TestJob_EventWorkerDuplicatesObservationsAcrossActiveScopes(t *testing.T) {
	t.Parallel()

	job, eventCh := newTestJob(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"), jobcontext.JobMetadata{}, testEventChannelSize)
	if err := job.SetHostScope(testCtx, jobscope.NewHost()); err != nil {
		t.Fatalf("SetHostScope: %v", err)
	}
	if err := job.SetProjectScope(testCtx, jobscope.NewProject()); err != nil {
		t.Fatalf("SetProjectScope: %v", err)
	}
	t.Cleanup(func() {
		finishTestJob(job, eventCh)
	})

	sendTestEvent(t, eventCh, testDispatchEvent("/usr/bin/curl", "example.com", 443))

	waitForJob(t, "worker should duplicate observations into both scopes", func() bool {
		host := job.HostScope().ObservationSnapshot()
		project := job.ProjectScope().ObservationSnapshot()
		return len(host.ObservationNetwork.Records) == 1 && len(project.ObservationNetwork.Records) == 1
	})

	host := job.HostScope().ObservationSnapshot()
	project := job.ProjectScope().ObservationSnapshot()
	if host.ObservationNetwork.Records[0].RemoteIP != "example.com" || project.ObservationNetwork.Records[0].RemoteIP != "example.com" {
		t.Fatalf("network duplication: host=%v project=%v", host.ObservationNetwork.Records, project.ObservationNetwork.Records)
	}
}

func TestJob_EventScopeCountersAreLocal(t *testing.T) {
	t.Parallel()

	job, eventCh := newTestJob(jobcontext.GitLabJobIdentity("gitlab.example.com", "acme/example", "123"), jobcontext.JobMetadata{}, testEventChannelSize)
	if err := job.SetHostScope(testCtx, jobscope.NewHost()); err != nil {
		t.Fatalf("SetHostScope: %v", err)
	}
	if err := job.SetProjectScope(testCtx, jobscope.NewProject()); err != nil {
		t.Fatalf("SetProjectScope: %v", err)
	}

	sendTestEvent(t, eventCh, testDispatchEvent("/usr/bin/curl", "example.com", 443))
	finishTestJob(job, eventCh)

	host := job.HostScope().ObservationSnapshot()
	project := job.ProjectScope().ObservationSnapshot()
	if host.Counters.EventsTotal != 1 || project.Counters.EventsTotal != 1 {
		t.Fatalf("events_total should be scope-local duplicates: host=%d project=%d", host.Counters.EventsTotal, project.Counters.EventsTotal)
	}
}

func waitForJob(t *testing.T, reason string, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		<-ticker.C
	}

	t.Fatalf("timeout waiting: %s", reason)
}

func newTestJob(identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, eventChannelSize int) (*Job, chan jobevent.EventRecord) {
	eventCh := make(chan jobevent.EventRecord, eventChannelSize)
	return NewJob(testLogger, identity, metadata, "machine", eventCh), eventCh
}

func newTestJobWithoutWorker(identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata) *Job {
	return NewJob(testLogger, identity, metadata, "machine", nil)
}

func sendTestEvent(t *testing.T, eventCh chan<- jobevent.EventRecord, event jobevent.EventRecord) {
	t.Helper()
	eventCh <- event
}

func finishTestJob(job *Job, eventCh chan jobevent.EventRecord) {
	done := job.Done()
	job.MarkClosing()
	close(eventCh)
	<-done
}

func testDispatchEvent(execPath, host string, port int64) jobevent.EventRecord {
	return jobevent.EventRecord{
		EventType: jobevent.NetworkConnect,
		Timestamp: time.Date(2026, 4, 16, 1, 2, 3, 4, time.UTC),
		Payload: map[string]any{
			"remote_ip":   host,
			"remote_port": port,
			"protocol":    "tcp",
		},
		Process: jobevent.ProcessSummary{
			PID:      100,
			ExecPath: execPath,
		},
		Tags: map[string]string{},
	}
}
