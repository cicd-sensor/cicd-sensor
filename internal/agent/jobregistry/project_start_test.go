package jobregistry_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	jobpkg "github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestJobRegistry_ApplyGitHubProjectStart_SeedsProjectDefaultMaxAlerts(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	job, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:                id,
		Metadata:                meta,
		RunnerType:              "machine",
		DefaultMaxAlertsPerRule: 12,
	})
	if err != nil {
		t.Fatalf("apply project start: %v", err)
	}
	if job.ProjectScope() == nil {
		t.Fatal("expected project scope to be set")
	}
	if got := job.ProjectScope().DefaultMaxAlertsPerRule; got != 12 {
		t.Fatalf("project scope default_max_alerts_per_rule: got %d, want 12", got)
	}
}

func TestJobRegistry_ApplyGitHubProjectStart_AppliesProjectRules(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	collect := rule.RuleActionCollect
	job, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:   id,
		Metadata:   meta,
		RunnerType: "machine",
		RuleSources: []rulesource.LoadedRules{{
			RuleSets: []rule.RuleSet{{
				RulesetID: "project",
				Rules: []rule.Rule{{
					RuleID:    "project_exec",
					EventType: jobevent.ProcessExec,
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
				}},
			}},
			RuleModifiers: []rule.RuleModifier{{
				ModifierID:     "project-collect",
				Targets:        []rule.RuleModifierTarget{{RulesetID: "project", RuleID: "project_exec"}},
				OverrideAction: &collect,
			}},
		}},
	})
	if err != nil {
		t.Fatalf("apply project start: %v", err)
	}
	if got := len(job.ProjectScope().RuleSets); got != 1 {
		t.Fatalf("project scope rule_sets: got %d, want 1", got)
	}
	if got := len(job.ProjectScope().RuleModifiers); got != 1 {
		t.Fatalf("project scope rule_modifiers: got %d, want 1", got)
	}
	if got := len(job.ProjectScope().ResolvedRules.Rules); got != 1 {
		t.Fatalf("resolved rules: got %d, want 1", got)
	}
	if got := job.ProjectScope().ResolvedRules.Rules[0].Rule.Action; got != rule.RuleActionCollect {
		t.Fatalf("resolved action: got %q, want %q", got, rule.RuleActionCollect)
	}
}

func TestJobRegistry_ApplyGitHubProjectStart_ManagerConfigIgnoresLocalProjectInputs(t *testing.T) {
	svc := &fakeConfigService{
		handler: func(context.Context, *connect.Request[managerv1beta1.FetchConfigRequest]) (*connect.Response[managerv1beta1.FetchConfigResponse], error) {
			sources := mustRuleSources(t, []rule.RuleSet{{
				RulesetID: "managed-project",
				Rules: []rule.Rule{{
					RuleID:    "managed_exec",
					EventType: jobevent.ProcessExec,
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
				}},
			}}, nil)
			return connect.NewResponse(&managerv1beta1.FetchConfigResponse{
				Config: &managerv1beta1.ServedConfig{
					DefaultMaxAlertsPerRule: 29,
					OutputSettings: &managerv1beta1.OutputSettings{
						Summary: &managerv1beta1.OutputSetting{Enabled: true},
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
	localSources := []rulesource.LoadedRules{{
		RuleSets: []rule.RuleSet{{
			RulesetID: "local-project",
			Rules: []rule.Rule{{
				RuleID:    "local_exec",
				EventType: jobevent.ProcessExec,
				Condition: `process_name == "sh"`,
				Action:    rule.RuleActionDetect,
			}},
		}},
	}}

	job, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:                id,
		Metadata:                meta,
		RunnerType:              "machine",
		DefaultMaxAlertsPerRule: 12,
		RuleSources:             localSources,
		ManagerConnection: managerclient.Connection{
			BaseURL: server.URL,
			Token:   testManagerToken,
		},
		ManagerClient: client,
	})
	if err != nil {
		t.Fatalf("apply project start: %v", err)
	}

	project := job.ProjectScope()
	if project == nil {
		t.Fatal("expected project scope")
	}
	if got := len(project.RuleSets); got != 1 {
		t.Fatalf("project rule_sets: got %d, want 1", got)
	}
	if got := project.RuleSets[0].RulesetID; got != "managed-project" {
		t.Fatalf("project ruleset id: got %q, want managed-project", got)
	}
	if got := project.DefaultMaxAlertsPerRule; got != 29 {
		t.Fatalf("project default_max_alerts_per_rule: got %d, want 29", got)
	}
	if !project.ManagerJobLogsForTesting().HasWorkersForTesting() {
		t.Fatal("expected manager job logs from manager output settings")
	}
}

func TestJobRegistry_ApplyGitHubProjectStart_SetsProjectScopeOnNewJob(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	job, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:   id,
		Metadata:   meta,
		RunnerType: "machine",
	})
	if err != nil {
		t.Fatalf("apply project start: %v", err)
	}
	if job.ProjectScope() == nil {
		t.Fatal("expected project scope to be set")
	}
}

func TestJobRegistry_ApplyGitHubProjectStart_UpdatesExistingJob(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	hostMeta := jobcontext.JobMetadata{}
	projectMeta := jobcontext.JobMetadata{}

	job, err := jr.ApplyGitHubHostStart(testCtx, id, hostMeta, "machine", 0, managerclient.Connection{}, staticManagerFetcher{})
	if err != nil {
		t.Fatalf("apply host start: %v", err)
	}
	got, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:   id,
		Metadata:   projectMeta,
		RunnerType: "machine",
	})
	if err != nil {
		t.Fatalf("apply project start: %v", err)
	}
	if got != job {
		t.Fatal("expected project start to update existing job")
	}
	if got.HostScope() == nil {
		t.Fatal("expected host scope to remain set")
	}
	if got.ProjectScope() == nil {
		t.Fatal("expected project scope to be set")
	}
}

func TestJobRegistry_ApplyGitHubProjectStart_DuplicateReturnsError(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	if _, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:   id,
		Metadata:   meta,
		RunnerType: "machine",
	}); err != nil {
		t.Fatalf("first project start: %v", err)
	}
	if _, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:   id,
		Metadata:   meta,
		RunnerType: "machine",
	}); !errors.Is(err, jobpkg.ErrProjectScopeAlreadySet) {
		t.Fatalf("second project start error: got %v, want %v", err, jobpkg.ErrProjectScopeAlreadySet)
	}
}

func TestJobRegistry_ApplyGitHubProjectStart_PendingDuplicateReturnsError(t *testing.T) {
	fetcher := &slowFetcher{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	startDone := make(chan error, 1)
	go func() {
		_, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
			Identity:      id,
			Metadata:      meta,
			RunnerType:    "machine",
			ManagerClient: fetcher,
		})
		startDone <- err
	}()

	select {
	case <-fetcher.started:
	case <-time.After(2 * time.Second):
		t.Fatal("ApplyGitHubProjectStart did not reach manager fetch within timeout")
	}

	_, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:   id,
		Metadata:   meta,
		RunnerType: "machine",
	})
	if !errors.Is(err, jobregistry.ErrJobAlreadyRegistered) {
		t.Fatalf("in-flight duplicate project start: got %v, want %v", err, jobregistry.ErrJobAlreadyRegistered)
	}

	close(fetcher.release)
	if err := <-startDone; err != nil {
		t.Fatalf("first ApplyGitHubProjectStart: %v", err)
	}
}
