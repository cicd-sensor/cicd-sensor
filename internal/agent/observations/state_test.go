package observations

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestNilStateNoopsAndReturnsZeroSnapshot(t *testing.T) {
	t.Parallel()

	var state *State

	state.RecordEvent(jobevent.EventRecord{EventType: jobevent.ProcessExec})
	state.RecordDroppedEvent()
	state.FeedHit(HitEntry{
		Identity: rule.RuleIdentity{RulesetID: "set", RuleID: "rule"},
		Action:   string(rule.RuleActionDetect),
	}, jobevent.EventRecord{EventType: jobevent.ProcessExec})

	if got := state.CorrelationHitCountFor(rule.RuleIdentity{RulesetID: "set", RuleID: "rule"}); got != 0 {
		t.Fatalf("nil state CorrelationHitCountFor: got %d, want 0", got)
	}
	snapshot := state.Snapshot()
	if snapshot.Counters.EventsTotal != 0 || snapshot.Counters.EventsDropped != 0 {
		t.Fatalf("nil state counters: got %#v, want zero", snapshot.Counters)
	}
	if len(snapshot.Hits) != 0 {
		t.Fatalf("nil state hits length: got %d, want 0", len(snapshot.Hits))
	}
}

func TestState_RecordDroppedEventIncrementsDroppedCounter(t *testing.T) {
	t.Parallel()

	state := NewState()
	state.RecordEvent(jobevent.EventRecord{EventType: jobevent.ProcessExec})
	state.RecordDroppedEvent()
	state.RecordDroppedEvent()

	snapshot := state.Snapshot()
	if got := snapshot.Counters.EventsTotal; got != 1 {
		t.Fatalf("events total: got %d, want 1", got)
	}
	if got := snapshot.Counters.EventsDropped; got != 2 {
		t.Fatalf("events dropped: got %d, want 2", got)
	}
}
