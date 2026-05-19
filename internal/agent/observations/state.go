// Package observations holds the bounded facts accumulated while a job scope
// processes events.
package observations

import (
	"sync"
	"sync/atomic"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

const observationCap = 1000
const observationProcessCap = 10

// State is the bounded live observation state for one scope.
type State struct {
	counters eventCounters

	mu       sync.Mutex
	ruleHits map[rule.RuleIdentity]*ruleState
	domains  map[string]*domainObservation
	networks map[networkObservationKey]*networkObservation

	domainOverflow  int64
	networkOverflow int64
}

type eventCounters struct {
	EventsTotal   atomic.Int64
	EventsDropped atomic.Int64
}

func NewState() *State {
	return &State{
		ruleHits: make(map[rule.RuleIdentity]*ruleState),
		domains:  make(map[string]*domainObservation),
		networks: make(map[networkObservationKey]*networkObservation),
	}
}

type domainObservation struct {
	processContexts processContexts
}

type networkObservationKey struct {
	remoteIP   string
	remotePort int64
	protocol   string
}

type networkObservation struct {
	processContexts processContexts
}

type processContexts struct {
	processes map[processObservationKey]ProcessContext
	overflow  int64
}

type processObservationKey struct {
	pid           int32
	startBoottime uint64
}

func (s *State) RecordDroppedEvent() {
	if s == nil {
		return
	}
	s.counters.EventsDropped.Add(1)
}

func (s *State) Snapshot() StateSnapshot {
	if s == nil {
		return StateSnapshot{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return StateSnapshot{
		Counters:           s.counters.snapshot(),
		Hits:               s.hitSnapshotLocked(),
		ObservationDomain:  s.domainSnapshotLocked(),
		ObservationNetwork: s.networkSnapshotLocked(),
	}
}
