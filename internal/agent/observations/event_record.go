package observations

import (
	"strconv"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

func (s *State) RecordEvent(event jobevent.EventRecord) {
	if s == nil {
		return
	}
	s.counters.EventsTotal.Add(1)

	switch event.EventType {
	case jobevent.Domain:
		domain, _ := event.Payload["domain"].(string)
		if domain == "" {
			return
		}
		s.recordDomain(domain, event.Process)
	case jobevent.NetworkConnect:
		ip, _ := event.Payload["remote_ip"].(string)
		if ip == "" {
			return
		}
		port, ok := payloadInt64(event.Payload, "remote_port")
		if !ok {
			return
		}
		protocol, _ := event.Payload["protocol"].(string)
		if protocol == "" {
			return
		}
		s.recordNetwork(networkObservationKey{remoteIP: ip, remotePort: port, protocol: protocol}, event.Process)
	}
}

func (s *State) recordDomain(domain string, process jobevent.ProcessSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if observation, exists := s.domains[domain]; exists {
		addProcessContext(&observation.processContexts, process)
		return
	}
	if len(s.domains) >= observationCap {
		s.domainOverflow++
		return
	}
	observation := &domainObservation{processContexts: newProcessContexts()}
	addProcessContext(&observation.processContexts, process)
	s.domains[domain] = observation
}

func (s *State) recordNetwork(key networkObservationKey, process jobevent.ProcessSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if observation, exists := s.networks[key]; exists {
		addProcessContext(&observation.processContexts, process)
		return
	}
	if len(s.networks) >= observationCap {
		s.networkOverflow++
		return
	}
	observation := &networkObservation{processContexts: newProcessContexts()}
	addProcessContext(&observation.processContexts, process)
	s.networks[key] = observation
}

func newProcessContexts() processContexts {
	return processContexts{processes: make(map[processObservationKey]ProcessContext)}
}

func addProcessContext(contexts *processContexts, process jobevent.ProcessSummary) {
	context := processContextFromSummary(process)
	if context.PID == 0 && context.StartBoottime == 0 && context.ExecPath == "" {
		return
	}
	key := processObservationKey{
		pid:           context.PID,
		startBoottime: context.StartBoottime,
	}
	if _, exists := contexts.processes[key]; exists {
		if processHasContext(context) {
			contexts.processes[key] = context
		}
		return
	}
	if len(contexts.processes) >= observationProcessCap {
		contexts.overflow++
		return
	}
	contexts.processes[key] = context
}

func processContextFromSummary(process jobevent.ProcessSummary) ProcessContext {
	context := ProcessContext{
		PID:           process.PID,
		StartBoottime: process.StartBoottime,
		ExecPath:      process.ExecPath,
	}
	if len(process.Ancestors) > 0 {
		context.Ancestors = make([]ProcessAncestorContext, 0, len(process.Ancestors))
		for _, ancestor := range process.Ancestors {
			if ancestor.ExecPath == "" {
				continue
			}
			context.Ancestors = append(context.Ancestors, ProcessAncestorContext{ExecPath: ancestor.ExecPath})
		}
	}
	return context
}

func processHasContext(process ProcessContext) bool {
	return process.ExecPath != "" || len(process.Ancestors) > 0
}

func payloadInt64(payload map[string]any, key string) (int64, bool) {
	switch value := payload[key].(type) {
	case int:
		return int64(value), true
	case int32:
		return int64(value), true
	case int64:
		return value, true
	case uint16:
		return int64(value), true
	case uint32:
		return int64(value), true
	case float64:
		if value != float64(int64(value)) {
			return 0, false
		}
		return int64(value), true
	case string:
		parsed, err := strconv.ParseInt(value, 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}
