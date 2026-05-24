package kerneltracker

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

func TestHandleNetConnectV4Sample_EmitsPayloadAndBlockTag(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "network-v4")
	identity := processIdentity{PID: 101, StartBoottime: 2}
	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "/usr/bin/curl", nil, 0)

	effects := handleNetConnectV4Sample(state, netConnectV4Sample{
		Identity:   identity,
		CgroupID:   42,
		RemoteIPv4: [4]byte{192, 0, 2, 10},
		Port:       443,
		Protocol:   6,
		Blocked:    true,
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	if emit.Record.EventType != jobevent.NetworkConnect {
		t.Fatalf("kind = %q, want %q", emit.Record.EventType, jobevent.NetworkConnect)
	}
	assertNetworkConnectPayload(t, emit.Record, "192.0.2.10", 443, "tcp", "ipv4")
	if got := emit.Record.Tags["block_source"]; got != "kernel" {
		t.Fatalf("block_source tag = %q, want kernel", got)
	}
}

func TestHandleNetConnectV6Sample_EmitsPayload(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "network-v6")
	identity := processIdentity{PID: 101, StartBoottime: 2}
	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "/usr/bin/curl", nil, 0)

	effects := handleNetConnectV6Sample(state, netConnectV6Sample{
		Identity:   identity,
		CgroupID:   42,
		RemoteIPv6: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Port:       53,
		Protocol:   17,
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	if emit.Record.EventType != jobevent.NetworkConnect {
		t.Fatalf("kind = %q, want %q", emit.Record.EventType, jobevent.NetworkConnect)
	}
	assertNetworkConnectPayload(t, emit.Record, "2001:db8::1", 53, "udp", "ipv6")
	if got := emit.Record.Tags["block_source"]; got != "" {
		t.Fatalf("block_source tag = %q, want empty", got)
	}
}

func TestHandleNetConnectSamples_DropZeroPort(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "network-zero-port")
	state := destinationTrackedState(jobID, 42)

	v4Effects := handleNetConnectV4Sample(state, netConnectV4Sample{
		CgroupID:   42,
		RemoteIPv4: [4]byte{192, 0, 2, 10},
		Port:       0,
		Protocol:   17,
	})
	if len(v4Effects) != 0 {
		t.Fatalf("v4 effects = %#v, want none", v4Effects)
	}

	v6Effects := handleNetConnectV6Sample(state, netConnectV6Sample{
		CgroupID:   42,
		RemoteIPv6: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Port:       0,
		Protocol:   17,
	})
	if len(v6Effects) != 0 {
		t.Fatalf("v6 effects = %#v, want none", v6Effects)
	}
}

func TestHandleNetConnectV4Sample_UnknownProtocol(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "network-unknown")
	state := destinationTrackedState(jobID, 42)

	effects := handleNetConnectV4Sample(state, netConnectV4Sample{
		CgroupID:   42,
		RemoteIPv4: [4]byte{203, 0, 113, 10},
		Port:       1,
		Protocol:   1,
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	assertNetworkConnectPayload(t, emit.Record, "203.0.113.10", 1, "unknown", "ipv4")
}

func TestHandleNetConnectV6Sample_UnknownProtocol(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "network-v6-unknown")
	state := destinationTrackedState(jobID, 42)

	effects := handleNetConnectV6Sample(state, netConnectV6Sample{
		CgroupID:   42,
		RemoteIPv6: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		Port:       1,
		Protocol:   1,
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	assertNetworkConnectPayload(t, emit.Record, "2001:db8::2", 1, "unknown", "ipv6")
}

func assertNetworkConnectPayload(t *testing.T, record jobevent.EventRecord, remoteIP string, remotePort int, protocol, family string) {
	t.Helper()

	if got, _ := record.Payload["remote_ip"].(string); got != remoteIP {
		t.Fatalf("payload[remote_ip] = %q, want %q", got, remoteIP)
	}
	if got, _ := record.Payload["remote_port"].(int); got != remotePort {
		t.Fatalf("payload[remote_port] = %d, want %d", got, remotePort)
	}
	if got, _ := record.Payload["protocol"].(string); got != protocol {
		t.Fatalf("payload[protocol] = %q, want %q", got, protocol)
	}
	if got, _ := record.Payload["family"].(string); got != family {
		t.Fatalf("payload[family] = %q, want %q", got, family)
	}
}

func TestRemoteIPAndFamily(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "ipv4_mapped_dual_stack_dest",
			// AF_INET6 socket connecting to 1.1.1.1 produces ::ffff:1.1.1.1 on
			// the jobcontext. We must surface it as 1.1.1.1 so a rule like
			// remote_ip == "1.1.1.1" matches the AF_INET6 path too.
			raw:  []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 1, 1, 1},
			want: "1.1.1.1",
		},
		{
			name: "loopback_v4_mapped",
			raw:  []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1},
			want: "127.0.0.1",
		},
		{
			name: "native_ipv6",
			// 2001:db8::1 — non-mapped IPv6 stays as v6 string.
			raw:  []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want: "2001:db8::1",
		},
		{
			name: "ipv6_loopback",
			raw:  []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want: "::1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, _ := remoteIPAndFamily(tc.raw)
			if got != tc.want {
				t.Fatalf("remoteIPAndFamily(%v): got %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
