package observations

import (
	"fmt"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

func TestState_RecordEventAggregatesDomains(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 5, 11, 1, 2, 3, 0, time.UTC)
	for i, domain := range []string{"b.example.com", "a.example.com", "b.example.com"} {
		state.RecordEvent(jobevent.EventRecord{
			EventType: jobevent.Domain,
			Timestamp: now,
			Payload: map[string]any{
				"domain": domain,
			},
			Process: testProcess(int32(i+1), "/usr/bin/curl"),
		})
	}

	snapshot := state.Snapshot()
	if got := snapshot.Counters.EventsTotal; got != 3 {
		t.Fatalf("events total: got %d, want 3", got)
	}
	domains := snapshot.ObservationDomain
	if got := len(domains.Records); got != 2 {
		t.Fatalf("domain records length: got %d, want 2", got)
	}
	if got := domains.Records[0].Domain; got != "a.example.com" {
		t.Fatalf("first sorted domain: got %q, want a.example.com", got)
	}
	if got := len(domains.Records[1].Processes); got != 2 {
		t.Fatalf("b.example.com process contexts: got %d, want 2", got)
	}
}

func TestState_RecordEventCapsDomainSnapshot(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 5, 11, 1, 2, 3, 0, time.UTC)
	for i := range observationCap {
		state.RecordEvent(jobevent.EventRecord{
			EventType: jobevent.Domain,
			Timestamp: now,
			Payload: map[string]any{
				"domain": fmt.Sprintf("d-%04d.example.com", i),
			},
		})
	}
	for _, domain := range []string{"d-0000.example.com", "overflow-1.example.com", "overflow-2.example.com"} {
		state.RecordEvent(jobevent.EventRecord{
			EventType: jobevent.Domain,
			Timestamp: now,
			Payload: map[string]any{
				"domain": domain,
			},
		})
	}

	snapshot := state.Snapshot().ObservationDomain
	if got := len(snapshot.Records); got != observationCap {
		t.Fatalf("domain cap: got %d, want %d", got, observationCap)
	}
	if got := snapshot.OverflowCount; got != 2 {
		t.Fatalf("domain overflow: got %d, want 2", got)
	}
}

func TestState_RecordEventAggregatesNetworks(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 5, 11, 1, 2, 3, 0, time.UTC)
	records := []struct {
		payload map[string]any
		process jobevent.ProcessSummary
	}{
		{payload: map[string]any{"remote_ip": "192.0.2.10", "remote_port": int64(443), "protocol": "tcp"}, process: testProcess(100, "/usr/bin/curl")},
		{payload: map[string]any{"remote_ip": "192.0.2.10", "remote_port": int64(443), "protocol": "udp"}, process: testProcess(101, "/usr/bin/dig")},
		{payload: map[string]any{"remote_ip": "192.0.2.10", "remote_port": int64(443), "protocol": "tcp"}, process: testProcess(100, "/usr/bin/curl")},
		{payload: map[string]any{"remote_ip": "198.51.100.20", "remote_port": int64(443), "protocol": "tcp"}, process: testProcess(102, "/usr/bin/wget")},
	}
	for _, record := range records {
		state.RecordEvent(jobevent.EventRecord{
			EventType: jobevent.NetworkConnect,
			Timestamp: now,
			Payload:   record.payload,
			Process:   record.process,
		})
	}

	snapshot := state.Snapshot()
	if got := snapshot.Counters.EventsTotal; got != 4 {
		t.Fatalf("events total: got %d, want 4", got)
	}
	networks := snapshot.ObservationNetwork
	if got := len(networks.Records); got != 3 {
		t.Fatalf("network records length: got %d, want 3", got)
	}
	first := networks.Records[0]
	if first.RemoteIP != "192.0.2.10" || first.RemotePort != 443 || first.Protocol != "tcp" {
		t.Fatalf("first sorted network record: got %+v", first)
	}
	if got := len(first.Processes); got != 1 {
		t.Fatalf("deduped process contexts: got %d, want 1", got)
	}
}

func TestState_RecordEventDistinguishesProcessStartBoottime(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 5, 11, 1, 2, 3, 0, time.UTC)
	for _, process := range []jobevent.ProcessSummary{
		{PID: 100, StartBoottime: 20, ExecPath: "/usr/bin/curl"},
		{PID: 100, StartBoottime: 10, ExecPath: "/usr/bin/curl"},
		{PID: 100, StartBoottime: 10, ExecPath: "/usr/bin/curl"},
	} {
		state.RecordEvent(jobevent.EventRecord{
			EventType: jobevent.Domain,
			Timestamp: now,
			Payload:   map[string]any{"domain": "example.com"},
			Process:   process,
		})
	}

	processes := state.Snapshot().ObservationDomain.Records[0].Processes
	if got := len(processes); got != 2 {
		t.Fatalf("process contexts: got %d, want 2", got)
	}
	if got, want := processes[0].StartBoottime, uint64(10); got != want {
		t.Fatalf("first start_boottime = %d, want %d", got, want)
	}
	if got, want := processes[1].StartBoottime, uint64(20); got != want {
		t.Fatalf("second start_boottime = %d, want %d", got, want)
	}
}

func TestState_RecordEventDedupesProcessByPIDAndStartBoottime(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 5, 11, 1, 2, 3, 0, time.UTC)
	for _, process := range []jobevent.ProcessSummary{
		{PID: 100, StartBoottime: 10, ExecPath: "/usr/bin/curl"},
		{PID: 100, StartBoottime: 10, ExecPath: "/usr/bin/wget"},
	} {
		state.RecordEvent(jobevent.EventRecord{
			EventType: jobevent.Domain,
			Timestamp: now,
			Payload:   map[string]any{"domain": "example.com"},
			Process:   process,
		})
	}

	processes := state.Snapshot().ObservationDomain.Records[0].Processes
	if got := len(processes); got != 1 {
		t.Fatalf("process contexts: got %d, want 1", got)
	}
	if got, want := processes[0].ExecPath, "/usr/bin/wget"; got != want {
		t.Fatalf("stored exec path = %q, want later event snapshot %q", got, want)
	}
}

func TestState_RecordEventDoesNotOverwriteProcessContextWithEmptySnapshot(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 5, 11, 1, 2, 3, 0, time.UTC)
	for _, process := range []jobevent.ProcessSummary{
		{PID: 100, StartBoottime: 10, ExecPath: "/usr/bin/curl"},
		{PID: 100, StartBoottime: 10},
	} {
		state.RecordEvent(jobevent.EventRecord{
			EventType: jobevent.Domain,
			Timestamp: now,
			Payload:   map[string]any{"domain": "example.com"},
			Process:   process,
		})
	}

	processes := state.Snapshot().ObservationDomain.Records[0].Processes
	if got := len(processes); got != 1 {
		t.Fatalf("process contexts: got %d, want 1", got)
	}
	if got, want := processes[0].ExecPath, "/usr/bin/curl"; got != want {
		t.Fatalf("stored exec path = %q, want useful event snapshot %q", got, want)
	}
}

func TestState_RecordEventOmitsObservationProcessArgv(t *testing.T) {
	t.Parallel()

	state := NewState()
	state.RecordEvent(jobevent.EventRecord{
		EventType: jobevent.Domain,
		Timestamp: time.Date(2026, 5, 11, 1, 2, 3, 0, time.UTC),
		Payload:   map[string]any{"domain": "example.com"},
		Process: jobevent.ProcessSummary{
			PID:           100,
			StartBoottime: 10,
			ExecPath:      "/usr/bin/curl",
			Argv:          []string{"curl", "--token=secret"},
			Ancestors: []jobevent.AncestorProcess{{
				ExecPath: "/bin/bash",
				Argv:     []string{"bash", "-c", "secret"},
			}},
		},
	})

	process := state.Snapshot().ObservationDomain.Records[0].Processes[0]
	if got, want := process.ExecPath, "/usr/bin/curl"; got != want {
		t.Fatalf("exec path = %q, want %q", got, want)
	}
	if got := len(process.Ancestors); got != 1 {
		t.Fatalf("ancestors = %d, want 1", got)
	}
	if got, want := process.Ancestors[0].ExecPath, "/bin/bash"; got != want {
		t.Fatalf("ancestor exec path = %q, want %q", got, want)
	}
}

func TestState_RecordEventOverwritesPidOnlyProcessContextWhenDetailsArrive(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 5, 11, 1, 2, 3, 0, time.UTC)
	for _, process := range []jobevent.ProcessSummary{
		{PID: 100, StartBoottime: 10},
		{PID: 100, StartBoottime: 10, ExecPath: "/usr/bin/node"},
	} {
		state.RecordEvent(jobevent.EventRecord{
			EventType: jobevent.Domain,
			Timestamp: now,
			Payload:   map[string]any{"domain": "example.com"},
			Process:   process,
		})
	}

	processes := state.Snapshot().ObservationDomain.Records[0].Processes
	if got := len(processes); got != 1 {
		t.Fatalf("process contexts: got %d, want 1", got)
	}
	if got, want := processes[0].ExecPath, "/usr/bin/node"; got != want {
		t.Fatalf("stored exec path = %q, want later process context %q", got, want)
	}
}

func TestState_RecordEventSkipsEmptyProcessContext(t *testing.T) {
	t.Parallel()

	state := NewState()
	state.RecordEvent(jobevent.EventRecord{
		EventType: jobevent.Domain,
		Timestamp: time.Date(2026, 5, 11, 1, 2, 3, 0, time.UTC),
		Payload:   map[string]any{"domain": "example.com"},
	})

	record := state.Snapshot().ObservationDomain.Records[0]
	if got := len(record.Processes); got != 0 {
		t.Fatalf("process contexts: got %d, want 0", got)
	}
	if got := record.ProcessOverflowCount; got != 0 {
		t.Fatalf("process overflow: got %d, want 0", got)
	}
}

func TestState_RecordEventCapsNetworkSnapshot(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 5, 11, 1, 2, 3, 0, time.UTC)
	for i := range observationCap {
		state.RecordEvent(jobevent.EventRecord{
			EventType: jobevent.NetworkConnect,
			Timestamp: now,
			Payload: map[string]any{
				"remote_ip":   fmt.Sprintf("192.0.2.%d", i),
				"remote_port": int64(443),
				"protocol":    "tcp",
			},
		})
	}
	for _, ip := range []string{"192.0.2.0", "198.51.100.1", "198.51.100.2"} {
		state.RecordEvent(jobevent.EventRecord{
			EventType: jobevent.NetworkConnect,
			Timestamp: now,
			Payload: map[string]any{
				"remote_ip":   ip,
				"remote_port": int64(443),
				"protocol":    "tcp",
			},
		})
	}

	snapshot := state.Snapshot().ObservationNetwork
	if got := len(snapshot.Records); got != observationCap {
		t.Fatalf("network cap: got %d, want %d", got, observationCap)
	}
	if got := snapshot.OverflowCount; got != 2 {
		t.Fatalf("network overflow: got %d, want 2", got)
	}
}

func TestState_RecordEventCountsMalformedObservationPayloads(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 5, 11, 1, 2, 3, 0, time.UTC)
	for _, event := range []jobevent.EventRecord{
		{EventType: jobevent.Domain, Timestamp: now},
		{EventType: jobevent.Domain, Timestamp: now, Payload: map[string]any{"domain": ""}},
		{EventType: jobevent.Domain, Timestamp: now, Payload: map[string]any{"domain": 123}},
		{EventType: jobevent.NetworkConnect, Timestamp: now},
		{EventType: jobevent.NetworkConnect, Timestamp: now, Payload: map[string]any{"remote_ip": ""}},
		{EventType: jobevent.NetworkConnect, Timestamp: now, Payload: map[string]any{"remote_ip": 123}},
		{EventType: jobevent.NetworkConnect, Timestamp: now, Payload: map[string]any{"remote_ip": "192.0.2.1", "remote_port": "bad", "protocol": "tcp"}},
		{EventType: jobevent.NetworkConnect, Timestamp: now, Payload: map[string]any{"remote_ip": "192.0.2.1", "remote_port": int64(443), "protocol": ""}},
		{EventType: jobevent.ProcessExec, Timestamp: now},
	} {
		state.RecordEvent(event)
	}

	snapshot := state.Snapshot()
	if got := snapshot.Counters.EventsTotal; got != 9 {
		t.Fatalf("events total: got %d, want 9", got)
	}
	if got := len(snapshot.ObservationDomain.Records); got != 0 {
		t.Fatalf("domain records length: got %d, want 0", got)
	}
	if got := len(snapshot.ObservationNetwork.Records); got != 0 {
		t.Fatalf("network records length: got %d, want 0", got)
	}
}

func TestState_RecordEventCapsProcessContextsPerObservation(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 5, 11, 1, 2, 3, 0, time.UTC)
	for i := range observationProcessCap + 1 {
		process := testProcess(int32(i+1), fmt.Sprintf("/usr/bin/tool-%02d", i))
		state.RecordEvent(jobevent.EventRecord{
			EventType: jobevent.Domain,
			Timestamp: now,
			Payload:   map[string]any{"domain": "registry.npmjs.org"},
			Process:   process,
		})
		state.RecordEvent(jobevent.EventRecord{
			EventType: jobevent.NetworkConnect,
			Timestamp: now,
			Payload: map[string]any{
				"remote_ip":   "203.0.113.10",
				"remote_port": int64(443),
				"protocol":    "tcp",
			},
			Process: process,
		})
	}

	snapshot := state.Snapshot()
	if got := len(snapshot.ObservationDomain.Records[0].Processes); got != observationProcessCap {
		t.Fatalf("domain process cap: got %d, want %d", got, observationProcessCap)
	}
	if got := snapshot.ObservationDomain.Records[0].ProcessOverflowCount; got != 1 {
		t.Fatalf("domain process overflow: got %d, want 1", got)
	}
	if got := len(snapshot.ObservationNetwork.Records[0].Processes); got != observationProcessCap {
		t.Fatalf("network process cap: got %d, want %d", got, observationProcessCap)
	}
	if got := snapshot.ObservationNetwork.Records[0].ProcessOverflowCount; got != 1 {
		t.Fatalf("network process overflow: got %d, want 1", got)
	}
}

func TestState_RecordEventDoesNotOverflowDuplicateProcessContext(t *testing.T) {
	t.Parallel()

	state := NewState()
	now := time.Date(2026, 5, 11, 1, 2, 3, 0, time.UTC)
	for i := range observationProcessCap {
		state.RecordEvent(jobevent.EventRecord{
			EventType: jobevent.Domain,
			Timestamp: now,
			Payload:   map[string]any{"domain": "registry.npmjs.org"},
			Process:   testProcess(int32(i+1), fmt.Sprintf("/usr/bin/tool-%02d", i)),
		})
	}
	state.RecordEvent(jobevent.EventRecord{
		EventType: jobevent.Domain,
		Timestamp: now,
		Payload:   map[string]any{"domain": "registry.npmjs.org"},
		Process:   testProcess(1, "/usr/bin/tool-00"),
	})

	record := state.Snapshot().ObservationDomain.Records[0]
	if got := len(record.Processes); got != observationProcessCap {
		t.Fatalf("process contexts: got %d, want %d", got, observationProcessCap)
	}
	if got := record.ProcessOverflowCount; got != 0 {
		t.Fatalf("process overflow: got %d, want 0", got)
	}
}

func testProcess(pid int32, execPath string) jobevent.ProcessSummary {
	return jobevent.ProcessSummary{PID: pid, StartBoottime: uint64(pid) * 100, ExecPath: execPath}
}
