package observations

import (
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func feedTestHit(s *State, hit HitEntry, timestamp time.Time) {
	s.FeedHit(hit, jobevent.EventRecord{Timestamp: timestamp})
}

func testHit(rulesetID, ruleID, action string) HitEntry {
	return HitEntry{
		Identity: rule.RuleIdentity{RulesetID: rulesetID, RuleID: ruleID},
		Action:   action,
	}
}

func TestState_FeedHitAggregatesRetainedEvents(t *testing.T) {
	t.Parallel()

	state := NewState()

	first := time.Date(2026, 4, 15, 10, 0, 0, 0, time.UTC)
	second := first.Add(2 * time.Minute)
	third := first.Add(3 * time.Minute)

	for _, event := range []struct {
		hit       HitEntry
		timestamp time.Time
	}{
		{hit: testHit("set", "rule-1", "detect"), timestamp: second},
		{hit: testHit("set", "rule-1", "detect"), timestamp: first},
		{hit: testHit("set", "rule-1", "detect"), timestamp: third},
	} {
		feedTestHit(state, event.hit, event.timestamp)
	}

	snapshot := state.Snapshot().Hits
	if len(snapshot) != 1 {
		t.Fatalf("hit snapshot length: got %d, want 1", len(snapshot))
	}
	hitSummary := snapshot[0]

	if hitSummary.HitCount != 3 {
		t.Fatalf("hit_count: got %d, want 3", hitSummary.HitCount)
	}
	if got := len(hitSummary.AlertEventRecords); got != 3 {
		t.Fatalf("hit events length: got %d, want 3", got)
	}
	if !hitSummary.AlertEventRecords[0].Timestamp.Equal(second.UTC()) {
		t.Fatalf("first retained event timestamp: got %s, want %s", hitSummary.AlertEventRecords[0].Timestamp, second.UTC())
	}
}

func TestState_HitSnapshotSortsByRuleIdentity(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 4, 15, 10, 0, 0, 0, time.UTC)
	for _, hit := range []HitEntry{
		testHit("set-b", "rule-a", "detect"),
		testHit("set-a", "rule-b", "detect"),
		testHit("set-a", "rule-a", "detect"),
	} {
		feedTestHit(state, hit, now)
	}

	snapshot := state.Snapshot().Hits
	if got := len(snapshot); got != 3 {
		t.Fatalf("hit snapshot length: got %d, want 3", got)
	}
	want := []rule.RuleIdentity{
		{RulesetID: "set-a", RuleID: "rule-a"},
		{RulesetID: "set-a", RuleID: "rule-b"},
		{RulesetID: "set-b", RuleID: "rule-a"},
	}
	for i, identity := range want {
		if snapshot[i].Identity != identity {
			t.Fatalf("snapshot[%d] identity: got %#v, want %#v", i, snapshot[i].Identity, identity)
		}
	}
}

func TestState_FeedClassifiesByAction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		action      string
		wantDetect  int
		wantCollect int
		wantPrevent int
	}{
		{name: "detect_hits_detect_view", action: "detect", wantDetect: 1},
		{name: "collect_hits_collect_view", action: "collect", wantCollect: 1},
		{name: "terminate_hits_prevent_view", action: "terminate", wantPrevent: 1},
		{name: "unknown_action_is_not_in_known_action_views", action: "unknown", wantDetect: 0, wantCollect: 0, wantPrevent: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			state := NewState()
			feedTestHit(state, testHit("set", "rule-1", tt.action), time.Date(2026, 4, 15, 10, 0, 0, 0, time.UTC))

			snapshot := state.Snapshot()
			if got := len(hitsWithAction(snapshot, rule.RuleActionDetect)); got != tt.wantDetect {
				t.Fatalf("hit_detect length: got %d, want %d", got, tt.wantDetect)
			}
			if got := len(hitsWithAction(snapshot, rule.RuleActionCollect)); got != tt.wantCollect {
				t.Fatalf("hit_collect length: got %d, want %d", got, tt.wantCollect)
			}
			if got := len(hitsWithAction(snapshot, rule.RuleActionTerminate)); got != tt.wantPrevent {
				t.Fatalf("hit_prevent length: got %d, want %d", got, tt.wantPrevent)
			}
		})
	}
}

func TestState_FeedHitIgnoresZeroIdentity(t *testing.T) {
	t.Parallel()

	state := NewState()
	state.FeedHit(HitEntry{
		Action: string(rule.RuleActionDetect),
	}, jobevent.EventRecord{EventType: jobevent.ProcessExec})

	if got := len(state.Snapshot().Hits); got != 0 {
		t.Fatalf("hit snapshot length: got %d, want 0", got)
	}
	if got := state.CorrelationHitCountFor(rule.RuleIdentity{}); got != 0 {
		t.Fatalf("CorrelationHitCountFor zero identity: got %d, want 0", got)
	}
}

func TestState_FeedHitRespectsMaxAlerts(t *testing.T) {
	t.Parallel()

	state := NewState()
	hit := testHit("set", "limited", "detect")
	hit.MaxAlerts = 2
	now := time.Date(2026, 4, 16, 1, 2, 3, 0, time.UTC)
	for i, id := range []string{"event-a", "event-b", "event-c"} {
		state.FeedHit(hit, jobevent.EventRecord{
			ID:        id,
			EventType: jobevent.ProcessExec,
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}

	snapshot := state.Snapshot().Hits
	if len(snapshot) != 1 {
		t.Fatalf("hit snapshot length: got %d, want 1", len(snapshot))
	}
	summary := snapshot[0]
	if got := summary.HitCount; got != 3 {
		t.Fatalf("hit count: got %d, want 3", got)
	}
	if got := len(summary.AlertEventRecords); got != 2 {
		t.Fatalf("retained event length: got %d, want 2", got)
	}
	if got := summary.AlertEventRecords[0].ID; got != "event-a" {
		t.Fatalf("first retained event ID: got %q, want event-a", got)
	}
	if got := summary.AlertEventRecords[1].ID; got != "event-b" {
		t.Fatalf("second retained event ID: got %q, want event-b", got)
	}
}

func TestState_FeedHitRetainsAllEventsWhenMaxAlertsUnsetOrNegative(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		maxAlerts int
	}{
		{name: "unset", maxAlerts: 0},
		{name: "negative", maxAlerts: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			state := NewState()
			hit := testHit("set", tt.name, "detect")
			hit.MaxAlerts = tt.maxAlerts
			now := time.Date(2026, 4, 16, 1, 2, 3, 0, time.UTC)
			for i := range 3 {
				state.FeedHit(hit, jobevent.EventRecord{
					EventType: jobevent.ProcessExec,
					Timestamp: now.Add(time.Duration(i) * time.Second),
				})
			}

			summary := state.Snapshot().Hits[0]
			if got := summary.HitCount; got != 3 {
				t.Fatalf("hit count: got %d, want 3", got)
			}
			if got := len(summary.AlertEventRecords); got != 3 {
				t.Fatalf("retained event length: got %d, want 3", got)
			}
		})
	}
}

func TestState_CorrelationHitCountForAggregatesAcrossActions(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 4, 16, 1, 2, 3, 0, time.UTC)

	for _, action := range []string{
		string(rule.RuleActionDetect),
		string(rule.RuleActionCollect),
		string(rule.RuleActionTerminate),
	} {
		feedTestHit(state, testHit("shared-set", "rule-1", action), now)
	}

	identity := rule.RuleIdentity{RulesetID: "shared-set", RuleID: "rule-1"}
	if got := state.CorrelationHitCountFor(identity); got != 3 {
		t.Fatalf("CorrelationHitCountFor: got %d, want 3", got)
	}
}

func TestState_CorrelationHitCountForReturnsZeroForUnseenRule(t *testing.T) {
	t.Parallel()

	state := NewState()

	if got := state.CorrelationHitCountFor(rule.RuleIdentity{}); got != 0 {
		t.Fatalf("CorrelationHitCountFor for zero identity: got %d, want 0", got)
	}
	if got := state.CorrelationHitCountFor(rule.RuleIdentity{RulesetID: "set-a", RuleID: "missing"}); got != 0 {
		t.Fatalf("CorrelationHitCountFor for unseen rule: got %d, want 0", got)
	}

	// CorrelationHitCountFor must not fabricate hit entries: Hit Views stay empty.
	snapshot := state.Snapshot()
	if got := len(snapshot.Hits); got != 0 {
		t.Fatalf("Hit Views after lookup-only access: got %d, want 0", got)
	}
}

func TestState_HitSnapshotClonesEventRecordSlice(t *testing.T) {
	t.Parallel()

	state := NewState()
	state.FeedHit(testHit("set", "rule-1", "detect"), jobevent.EventRecord{
		ID:        "original",
		EventType: jobevent.ProcessExec,
	})

	first := state.Snapshot().Hits
	first[0].AlertEventRecords[0] = jobevent.EventRecord{ID: "mutated"}

	second := state.Snapshot().Hits
	if got := second[0].AlertEventRecords[0].ID; got != "original" {
		t.Fatalf("stored event ID after mutating snapshot: got %q, want original", got)
	}
}

func TestState_FeedHitStoresProvidedEvent(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)

	state.FeedHit(testHit("set", "curl", "detect"), jobevent.EventRecord{
		EventType: jobevent.ProcessExec,
		Timestamp: now,
		Process: jobevent.ProcessSummary{
			PID:      100,
			ExecPath: "/usr/bin/curl",
			Argv:     []string{"curl", "--token=supersecret", "https://api.example.com"},
			Ancestors: []jobevent.AncestorProcess{
				{ExecPath: "/bin/bash", Argv: []string{"bash", "-c", "Bearer abc123"}},
			},
		},
	})

	snapshot := state.Snapshot().Hits
	if len(snapshot) != 1 || len(snapshot[0].AlertEventRecords) != 1 {
		t.Fatalf("expected 1 hit with 1 detail, got %#v", snapshot)
	}
	stored := snapshot[0].AlertEventRecords[0].Process

	if got, want := stored.Argv[1], "--token=supersecret"; got != want {
		t.Fatalf("stored argv: got %q, want %q", got, want)
	}
	if len(stored.Ancestors) != 1 {
		t.Fatalf("ancestors count: got %d, want 1", len(stored.Ancestors))
	}
	ancestor := stored.Ancestors[0]
	if ancestor.ExecPath != "/bin/bash" {
		t.Fatalf("ancestor exec_path must be preserved, got %q", ancestor.ExecPath)
	}
	if got, want := ancestor.Argv[2], "Bearer abc123"; got != want {
		t.Fatalf("stored ancestor argv: got %q, want %q", got, want)
	}
}

func hitsWithAction(snapshot StateSnapshot, action rule.RuleAction) HitSnapshot {
	out := make(HitSnapshot, 0, len(snapshot.Hits))
	for _, hit := range snapshot.Hits {
		if hit.Action == string(action) {
			out = append(out, hit)
		}
	}
	return out
}
