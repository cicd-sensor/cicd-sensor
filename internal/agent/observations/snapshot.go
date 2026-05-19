package observations

import (
	"cmp"
	"slices"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

type StateCountersSnapshot struct {
	EventsTotal   int64 `json:"events_total"`
	EventsDropped int64 `json:"events_dropped"`
}

type HitSummary struct {
	Identity          rule.RuleIdentity      `json:"-"`
	RulesetID         string                 `json:"ruleset_id"`
	RuleID            string                 `json:"rule_id"`
	RulesetRevision   string                 `json:"ruleset_revision,omitempty"`
	Action            string                 `json:"action"`
	HitCount          int64                  `json:"hit_count"`
	MaxAlerts         int                    `json:"max_alerts"`
	AlertEventRecords []jobevent.EventRecord `json:"alert_events,omitempty"`
}

type HitSnapshot []HitSummary

type DomainObservationSnapshot struct {
	Records       []DomainObservationRecord `json:"records"`
	OverflowCount int64                     `json:"overflow_count"`
}

type NetworkObservationSnapshot struct {
	Records       []NetworkObservationRecord `json:"records"`
	OverflowCount int64                      `json:"overflow_count"`
}

// ProcessContext is the bounded process identity kept for domain/network
// observations. It intentionally omits argv; reports need paths for context,
// not command-line secrets.
type ProcessContext struct {
	PID           int32                    `json:"pid,omitempty"`
	StartBoottime uint64                   `json:"start_boottime,omitempty"`
	ExecPath      string                   `json:"exec_path,omitempty"`
	Ancestors     []ProcessAncestorContext `json:"ancestors,omitempty"`
}

type ProcessAncestorContext struct {
	ExecPath string `json:"exec_path,omitempty"`
}

type DomainObservationRecord struct {
	Domain               string           `json:"domain"`
	Processes            []ProcessContext `json:"processes,omitempty"`
	ProcessOverflowCount int64            `json:"process_overflow_count,omitempty"`
}

type NetworkObservationRecord struct {
	RemoteIP             string           `json:"remote_ip"`
	RemotePort           int64            `json:"remote_port,omitempty"`
	Protocol             string           `json:"protocol,omitempty"`
	Processes            []ProcessContext `json:"processes,omitempty"`
	ProcessOverflowCount int64            `json:"process_overflow_count,omitempty"`
}

type StateSnapshot struct {
	Counters           StateCountersSnapshot      `json:"counters"`
	Hits               HitSnapshot                `json:"hits"`
	ObservationDomain  DomainObservationSnapshot  `json:"observation_domain"`
	ObservationNetwork NetworkObservationSnapshot `json:"observation_network"`
}

func (c *eventCounters) snapshot() StateCountersSnapshot {
	if c == nil {
		return StateCountersSnapshot{}
	}
	return StateCountersSnapshot{
		EventsTotal:   c.EventsTotal.Load(),
		EventsDropped: c.EventsDropped.Load(),
	}
}

func (s *State) hitSnapshotLocked() HitSnapshot {
	out := make(HitSnapshot, 0, len(s.ruleHits))
	for _, state := range s.ruleHits {
		out = append(out, HitSummary{
			Identity:          state.identity,
			RulesetID:         state.identity.RulesetID,
			RuleID:            state.identity.RuleID,
			RulesetRevision:   state.revision,
			Action:            state.action,
			HitCount:          state.hitCount,
			MaxAlerts:         state.maxAlerts,
			AlertEventRecords: slices.Clone(state.alertEventRecords),
		})
	}

	slices.SortFunc(out, func(left, right HitSummary) int {
		if diff := cmp.Compare(left.Identity.RulesetID, right.Identity.RulesetID); diff != 0 {
			return diff
		}
		return cmp.Compare(left.Identity.RuleID, right.Identity.RuleID)
	})
	return out
}

func (s *State) domainSnapshotLocked() DomainObservationSnapshot {
	records := make([]DomainObservationRecord, 0, len(s.domains))
	for domain, observation := range s.domains {
		records = append(records, DomainObservationRecord{
			Domain:               domain,
			Processes:            processContextSnapshot(observation.processContexts.processes),
			ProcessOverflowCount: observation.processContexts.overflow,
		})
	}
	slices.SortFunc(records, func(left, right DomainObservationRecord) int {
		return cmp.Compare(left.Domain, right.Domain)
	})

	return DomainObservationSnapshot{
		Records:       records,
		OverflowCount: s.domainOverflow,
	}
}

func (s *State) networkSnapshotLocked() NetworkObservationSnapshot {
	records := make([]NetworkObservationRecord, 0, len(s.networks))
	for key, observation := range s.networks {
		records = append(records, NetworkObservationRecord{
			RemoteIP:             key.remoteIP,
			RemotePort:           key.remotePort,
			Protocol:             key.protocol,
			Processes:            processContextSnapshot(observation.processContexts.processes),
			ProcessOverflowCount: observation.processContexts.overflow,
		})
	}
	slices.SortFunc(records, func(left, right NetworkObservationRecord) int {
		if diff := cmp.Compare(left.RemoteIP, right.RemoteIP); diff != 0 {
			return diff
		}
		if diff := cmp.Compare(left.RemotePort, right.RemotePort); diff != 0 {
			return diff
		}
		return cmp.Compare(left.Protocol, right.Protocol)
	})

	return NetworkObservationSnapshot{
		Records:       records,
		OverflowCount: s.networkOverflow,
	}
}

func processContextSnapshot(processes map[processObservationKey]ProcessContext) []ProcessContext {
	out := make([]ProcessContext, 0, len(processes))
	for _, process := range processes {
		out = append(out, process)
	}
	slices.SortFunc(out, func(left, right ProcessContext) int {
		if diff := cmp.Compare(left.PID, right.PID); diff != 0 {
			return diff
		}
		if diff := cmp.Compare(left.StartBoottime, right.StartBoottime); diff != 0 {
			return diff
		}
		return cmp.Compare(left.ExecPath, right.ExecPath)
	})
	return out
}
