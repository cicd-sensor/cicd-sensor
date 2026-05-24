package evaluation

import (
	"reflect"
	"sync"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestNewEvaluationState(t *testing.T) {
	t.Parallel()

	makeRule := func(ruleID, action string) rule.Rule {
		return rule.Rule{
			RuleID:    ruleID,
			Condition: `process.exec_path.endsWith("/bash")`,
			EventType: jobevent.ProcessExec,
			Action:    rule.RuleAction(action),
		}
	}

	tests := []struct {
		name      string
		host      *jobscope.JobScopeState
		project   *jobscope.JobScopeState
		wantRules int
		verify    func(t *testing.T, got *EvaluationState)
	}{
		{
			name:      "nil_host_nil_project_returns_empty_evaluation_state",
			wantRules: 0,
		},
		{
			name: "host_only_includes_host_rules",
			host: &jobscope.JobScopeState{
				ResolvedRules: resolvedRules("host-set", makeRule("r1", "detect")),
			},
			wantRules: 1,
			verify: func(t *testing.T, got *EvaluationState) {
				t.Helper()
				cr := got.RulesByType[jobevent.ProcessExec][0]
				if cr.CanonicalRuleID != "host-set/r1" {
					t.Fatalf("canonical rule ID: got %q, want %q", cr.CanonicalRuleID, "host-set/r1")
				}
				if cr.Action != rule.RuleActionDetect {
					t.Fatalf("action: got %q, want %q", cr.Action, rule.RuleActionDetect)
				}
				if !cr.FeedHost || cr.FeedProject {
					t.Fatalf("scope routing: got host=%v project=%v, want host=true project=false", cr.FeedHost, cr.FeedProject)
				}
			},
		},
		{
			name: "project_only_includes_project_rules",
			project: &jobscope.JobScopeState{
				ResolvedRules: resolvedRules("project-set", makeRule("r1", "detect")),
			},
			wantRules: 1,
			verify: func(t *testing.T, got *EvaluationState) {
				t.Helper()
				cr := got.RulesByType[jobevent.ProcessExec][0]
				if cr.CanonicalRuleID != "project-set/r1" {
					t.Fatalf("canonical rule ID: got %q, want %q", cr.CanonicalRuleID, "project-set/r1")
				}
				if cr.Action != rule.RuleActionDetect {
					t.Fatalf("action: got %q, want %q", cr.Action, rule.RuleActionDetect)
				}
				if cr.FeedHost || !cr.FeedProject {
					t.Fatalf("scope routing: got host=%v project=%v, want host=false project=true", cr.FeedHost, cr.FeedProject)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := NewEvaluationState(scopeResolvedRules(tt.host), scopeResolvedRules(tt.project))
			if got == nil {
				t.Fatal("expected evaluation state")
			}

			totalRules := 0
			for _, rules := range got.RulesByType {
				totalRules += len(rules)
			}
			if totalRules != tt.wantRules {
				t.Fatalf("rule count: got %d, want %d", totalRules, tt.wantRules)
			}

			if tt.verify != nil {
				tt.verify(t, got)
			}
		})
	}
}

func TestNewEvaluationState_DoesNotMutateExistingSummaryOnProjectAdd(t *testing.T) {
	t.Parallel()

	hostScope := newCorrelationScope("host-set", []rule.Rule{
		{
			RuleID:    "single",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		},
		{
			RuleID:    "corr",
			Type:      "correlation",
			Condition: `rule["single"].total_count >= 1 && rule["other"].total_count >= 1`,
			Action:    rule.RuleActionTerminate,
		},
	})
	projectScope := newProjectScopeWithRules("host-set", []rule.Rule{
		{
			RuleID:    "other",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "mirror.example.com"`,
			Action:    rule.RuleActionDetect,
		},
	})

	singleIdentity := rule.RuleIdentity{RulesetID: "host-set", RuleID: "single"}
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)
	hostScope.Observations.FeedHit(observations.HitEntry{
		Identity:  singleIdentity,
		Action:    string(rule.RuleActionDetect),
		MaxAlerts: 1,
	}, event)

	// Rebuild must not touch the existing scope's observations. Compare the
	// full render snapshot before / after NewEvaluationState so any mutation
	// to hit / observation state would show up.
	before := hostScope.ObservationSnapshot()

	eval := NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(projectScope))
	if eval == nil {
		t.Fatal("expected evaluation state")
	}

	after := hostScope.ObservationSnapshot()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("host observation snapshot changed during rebuild:\nbefore=%#v\nafter=%#v", before, after)
	}
	if got := len(detectHits(after)); got != 1 {
		t.Fatalf("host detect hit count after rebuild: got %d, want 1", got)
	}
}

func TestNewEvaluationState_SharedRuleEnvSupportsParallelBuilds(t *testing.T) {
	t.Parallel()

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()

			host := &jobscope.JobScopeState{
				ResolvedRules: resolvedRules("host-set", rule.Rule{
					RuleID:    "r1",
					Condition: `process.exec_path.endsWith("/bash")`,
					EventType: jobevent.ProcessExec,
					Action:    rule.RuleActionDetect,
				}),
			}
			got := NewEvaluationState(scopeResolvedRules(host), scopeResolvedRules(nil))
			if got == nil || len(got.RulesByType[jobevent.ProcessExec]) != 1 {
				t.Errorf("compiled rules: got %#v, want one process_exec rule", got)
			}
		}()
	}
	wg.Wait()
}
