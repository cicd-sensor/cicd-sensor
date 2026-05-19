package observations

import (
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

type ruleState struct {
	identity          rule.RuleIdentity
	revision          string
	action            string
	hitCount          int64
	maxAlerts         int
	alertEventRecords []jobevent.EventRecord
}

type HitEntry struct {
	Identity        rule.RuleIdentity
	RulesetRevision string
	Action          string
	MaxAlerts       int
}

func (s *State) FeedHit(hit HitEntry, event jobevent.EventRecord) {
	if s == nil || hit.Identity.IsZero() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.ruleHits[hit.Identity]
	if !ok {
		state = &ruleState{
			identity:  hit.Identity,
			revision:  hit.RulesetRevision,
			action:    hit.Action,
			maxAlerts: hit.MaxAlerts,
		}
		s.ruleHits[hit.Identity] = state
	}

	state.hitCount++
	if state.maxAlerts <= 0 || len(state.alertEventRecords) < state.maxAlerts {
		state.alertEventRecords = append(state.alertEventRecords, event)
	}
}

func (s *State) CorrelationHitCountFor(identity rule.RuleIdentity) int64 {
	if s == nil || identity.IsZero() {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.ruleHits[identity]
	if !ok {
		return 0
	}
	return state.hitCount
}
