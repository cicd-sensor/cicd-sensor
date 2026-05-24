package jobregistry_test

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	jobpkg "github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestJobRegistry_ApplyGitHubHostStart_RegistersAndGet(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	job, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", 0, managerclient.Connection{}, staticManagerFetcher{})
	if err != nil {
		t.Fatalf("apply host start: %v", err)
	}
	if job.State() != jobpkg.JobStateRunning {
		t.Errorf("state: got %q, want %q", job.State(), jobpkg.JobStateRunning)
	}

	got := registeredJob(jr, id)
	if got == nil {
		t.Fatal("expected to find registered job")
	}
	if got.Identity() != id {
		t.Errorf("identity: got %+v, want %+v", got.Identity(), id)
	}
}

func TestJobRegistry_ApplyGitHubHostStart_DuplicateReturnsError(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	if _, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", 0, managerclient.Connection{}, staticManagerFetcher{}); err != nil {
		t.Fatalf("first host start: %v", err)
	}
	if _, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", 0, managerclient.Connection{}, staticManagerFetcher{}); err == nil {
		t.Fatal("expected error on duplicate host start")
	}
}

func TestJobRegistry_ApplyGitHubHostStart_RequiresManager(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	job, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", 0, managerclient.Connection{}, nil)
	if !errors.Is(err, jobregistry.ErrHostManagerRequired) {
		t.Fatalf("apply host start: got %v, want %v", err, jobregistry.ErrHostManagerRequired)
	}
	if job != nil {
		t.Fatalf("job: got %#v, want nil", job)
	}
	if got := registeredJob(jr, id); got != nil {
		t.Fatalf("registered job: got %#v, want nil", got)
	}
}

func TestJobRegistry_ApplyGitHubHostStart_PendingDuplicateReturnsError(t *testing.T) {
	fetcher := &slowFetcher{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	startDone := make(chan error, 1)
	go func() {
		_, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", 0, managerclient.Connection{}, fetcher)
		startDone <- err
	}()

	select {
	case <-fetcher.started:
	case <-time.After(2 * time.Second):
		t.Fatal("ApplyGitHubHostStart did not reach manager fetch within timeout")
	}

	_, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", 0, managerclient.Connection{}, nil)
	if !errors.Is(err, jobregistry.ErrJobAlreadyRegistered) {
		t.Fatalf("in-flight duplicate host start: got %v, want %v", err, jobregistry.ErrJobAlreadyRegistered)
	}

	close(fetcher.release)
	if err := <-startDone; err != nil {
		t.Fatalf("first ApplyGitHubHostStart: %v", err)
	}
}

func TestJobRegistry_ApplyGitHubHostStart_UnwindsOnBindFailure(t *testing.T) {
	jr := newJobRegistry(t)
	kernelTracker, err := kerneltracker.New(testLogger, nil)
	if err != nil {
		t.Skipf("kernel tracker unavailable: %v", err)
	}
	jr.BindKernelTracker(kernelTracker)
	engineCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engineDone := make(chan error, 1)
	go func() { engineDone <- kernelTracker.Run(engineCtx) }()
	defer func() {
		cancel()
		<-engineDone
	}()

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	if _, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", math.MaxInt32, managerclient.Connection{}, staticManagerFetcher{}); err == nil {
		t.Fatal("expected apply host start to fail when BindProcessCgroupToJob errors")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if got := registeredJob(jr, id); got != nil {
			t.Errorf("job after failed apply: got %#v, want nil", got)
		}
		if jobs := jr.All(); len(jobs) != 0 {
			t.Errorf("All after failed apply: got %d jobs, want 0", len(jobs))
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("job registry methods blocked after ApplyGitHubHostStart returned an error")
	}
}

func TestJobRegistry_ApplyGitHubHostStart_SetsHostScope(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	job, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", 0, managerclient.Connection{}, staticManagerFetcher{})
	if err != nil {
		t.Fatalf("apply host start: %v", err)
	}
	if job.HostScope() == nil {
		t.Fatal("expected host scope to be set")
	}
	if job.RunnerType() != "machine" {
		t.Fatalf("job runner_type: got %q, want %q", job.RunnerType(), "machine")
	}
	if len(job.HostScope().ResolvedRules.Warnings) != 0 {
		t.Fatalf("host scope warnings: got %d, want 0", len(job.HostScope().ResolvedRules.Warnings))
	}
}

func TestJobRegistry_ApplyGitHubHostStart_AppliesManagerConfig(t *testing.T) {
	svc := &fakeConfigService{
		handler: func(_ context.Context, req *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error) {
			if req.Msg.RequestedOutputs != nil {
				t.Fatalf("requested outputs: got %+v, want nil", req.Msg.RequestedOutputs)
			}
			sources := mustRuleSources(t, []rule.RuleSet{{
				RulesetID: "managed",
				Rules: []rule.Rule{{
					RuleID:    "detect-1",
					EventType: jobevent.ProcessExec,
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
				}},
			}}, nil)
			return connect.NewResponse(&managerv1.FetchConfigResponse{
				Config: &managerv1.ServedConfig{
					ConfigRevision:          "sha256:test",
					DefaultMaxAlertsPerRule: 27,
					OutputSettings: &managerv1.OutputSettings{
						DetectionLog: &managerv1.OutputSetting{Enabled: true},
					},
				},
				RuleSources: sources,
			}), nil
		},
	}
	server := newFakeConfigServer(t, fakeConfigServerAddr, svc)
	defer server.Close()

	client := mustManagerClient(t, server.URL)
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	job, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", 0, managerclient.Connection{}, client)
	if err != nil {
		t.Fatalf("apply host start: %v", err)
	}
	if got := len(job.HostScope().RuleSets); got != 1 {
		t.Fatalf("host scope rule_sets: got %d, want 1", got)
	}
	if got := len(job.HostScope().ResolvedRules.Rules); got != 1 {
		t.Fatalf("host scope rules: got %d, want 1", got)
	}
	if got := job.HostScope().DefaultMaxAlertsPerRule; got != 27 {
		t.Fatalf("host scope default_max_alerts_per_rule: got %d, want 27", got)
	}
	if !job.HostScope().OutputSettings.GetDetectionLog().GetEnabled() {
		t.Fatal("host scope detection output: got false, want true")
	}
}

func TestJobRegistry_ManagerConfigDoesNotApplyToProjectScope(t *testing.T) {
	svc := &fakeConfigService{
		handler: func(context.Context, *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error) {
			sources := mustRuleSources(t, []rule.RuleSet{{
				RulesetID: "manager-host",
				Rules: []rule.Rule{{
					RuleID:    "host-only",
					EventType: jobevent.ProcessExec,
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
				}},
			}}, nil)
			return connect.NewResponse(&managerv1.FetchConfigResponse{
				Config: &managerv1.ServedConfig{
					DefaultMaxAlertsPerRule: 99,
					OutputSettings: &managerv1.OutputSettings{
						DetectionLog: &managerv1.OutputSetting{Enabled: true},
					},
				},
				RuleSources: sources,
			}), nil
		},
	}
	server := newFakeConfigServer(t, fakeConfigServerAddr, svc)
	defer server.Close()

	client := mustManagerClient(t, server.URL)
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	if _, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", 0, managerclient.Connection{}, client); err != nil {
		t.Fatalf("apply host start: %v", err)
	}
	collect := rule.RuleActionCollect
	job, err := jr.ApplyGitHubProjectStart(testCtx, id, meta, "machine", 0, 7, []rulesource.LoadedRules{{
		RuleSets: []rule.RuleSet{{
			RulesetID: "project",
			Rules: []rule.Rule{{
				RuleID:    "project-only",
				EventType: jobevent.ProcessExec,
				Condition: `process_name == "go"`,
				Action:    rule.RuleActionDetect,
			}},
		}},
		RuleModifiers: []rule.RuleModifier{{
			ModifierID:     "project-mod",
			Targets:        []rule.RuleModifierTarget{{RulesetID: "project", RuleID: "project-only"}},
			OverrideAction: &collect,
		}},
	}}, managerclient.Connection{}, nil, false)
	if err != nil {
		t.Fatalf("apply project start: %v", err)
	}

	if got := len(job.HostScope().ResolvedRules.Rules); got != 1 {
		t.Fatalf("host resolved rules: got %d, want 1", got)
	}
	project := job.ProjectScope()
	if project == nil {
		t.Fatal("expected project scope")
	}
	if got := len(project.RuleSets); got != 1 {
		t.Fatalf("project rule_sets: got %d, want 1", got)
	}
	if got := project.RuleSets[0].RulesetID; got != "project" {
		t.Fatalf("project ruleset id: got %q, want project", got)
	}
	if got := project.DefaultMaxAlertsPerRule; got != 7 {
		t.Fatalf("project default_max_alerts_per_rule: got %d, want 7", got)
	}
	if project.OutputSettings.GetDetectionLog().GetEnabled() {
		t.Fatal("project detection output: got true, want false")
	}
}

func TestJobRegistry_ApplyGitHubHostStart_ManagerFailureFailsClosed(t *testing.T) {
	svc := &fakeConfigService{
		handler: func(context.Context, *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error) {
			return nil, connect.NewError(connect.CodeInternal, errors.New("boom"))
		},
	}
	server := newFakeConfigServer(t, fakeConfigServerAddr, svc)
	defer server.Close()

	client := mustManagerClient(t, server.URL)
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	job, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", 0, managerclient.Connection{}, client)
	if err == nil {
		t.Fatal("expected manager fetch failure")
	}
	if !strings.Contains(err.Error(), "manager config fetch") {
		t.Fatalf("error = %v, want wrapped manager config fetch failure", err)
	}
	if job != nil {
		t.Fatalf("job = %v, want nil", job)
	}
}

func TestJobRegistry_ApplyGitLabHostStart_RequiresManager(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	meta := jobcontext.JobMetadata{}

	job, err := jr.ApplyGitLabHostStart(testCtx, id, meta, "machine", managerclient.Connection{}, nil)
	if !errors.Is(err, jobregistry.ErrHostManagerRequired) {
		t.Fatalf("apply gitlab host start: got %v, want %v", err, jobregistry.ErrHostManagerRequired)
	}
	if job != nil {
		t.Fatalf("job: got %#v, want nil", job)
	}
	if got := registeredJob(jr, id); got != nil {
		t.Fatalf("registered job: got %#v, want nil", got)
	}
}

func TestJobRegistry_ApplyGitHubHostStart_RejectsAfterProjectOnly(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	projectJob, err := jr.ApplyGitHubProjectStart(testCtx, id, meta, "machine", 0, 0, nil, managerclient.Connection{}, nil, false)
	if err != nil {
		t.Fatalf("apply project start: %v", err)
	}
	if projectJob.HostScope() != nil {
		t.Fatal("expected project-only job to have no host scope")
	}
	if projectJob.ProjectScope() == nil {
		t.Fatal("expected project-only job to have a project scope")
	}

	hostJob, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", 0, managerclient.Connection{}, nil)
	if !errors.Is(err, jobregistry.ErrHostAfterProject) {
		t.Fatalf("apply host start after project: got %v, want %v", err, jobregistry.ErrHostAfterProject)
	}
	if hostJob != nil {
		t.Fatalf("apply host start after project: got %#v, want nil", hostJob)
	}

	got := registeredJob(jr, id)
	if got == nil {
		t.Fatal("expected project-only job to remain registered")
	}
	if got.HostScope() != nil {
		t.Fatal("expected host scope to remain unset after rejected host start")
	}
	if got.ProjectScope() == nil {
		t.Fatal("expected project scope to remain set")
	}
}
