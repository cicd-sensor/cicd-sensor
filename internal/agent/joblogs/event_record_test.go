package joblogs

import (
	"reflect"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

func TestLogEventRecord_PayloadsAndTags(t *testing.T) {
	tests := []struct {
		name  string
		event jobevent.EventRecord
	}{
		{
			name: "network connect",
			event: jobevent.EventRecord{
				ID:        "event-1",
				EventType: jobevent.NetworkConnect,
				Tags:      map[string]string{"a": "1", "b": "2"},
				Payload: map[string]any{
					"remote_ip":   "1.2.3.4",
					"remote_port": 443,
					"protocol":    "tcp",
					"family":      "ipv4",
				},
			},
		},
		{
			name: "domain",
			event: jobevent.EventRecord{
				ID:        "event-2",
				EventType: jobevent.Domain,
				Payload: map[string]any{
					"domain": "example.com",
					"source": "dns",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := logEventRecord(tt.event)
			if got.Id != tt.event.ID || got.Type != string(tt.event.EventType) {
				t.Fatalf("event identity mismatch: %+v", got)
			}
			switch tt.event.EventType {
			case jobevent.NetworkConnect:
				if got.NetworkConnect == nil ||
					got.NetworkConnect.RemoteIp != "1.2.3.4" ||
					got.NetworkConnect.RemotePort != 443 ||
					got.NetworkConnect.Protocol != "tcp" ||
					got.NetworkConnect.Family != "ipv4" {
					t.Fatalf("network payload mismatch: %+v", got.NetworkConnect)
				}
				if !reflect.DeepEqual(got.Tags, []string{"a:1", "b:2"}) {
					t.Fatalf("tags: got %+v", got.Tags)
				}
			case jobevent.Domain:
				if got.Domain == nil || got.Domain.Name != "example.com" || got.Domain.Source != "dns" {
					t.Fatalf("domain payload mismatch: %+v", got.Domain)
				}
			}
		})
	}
}

func TestLogProcessSummary_DoesNotRedact(t *testing.T) {
	process := jobevent.ProcessSummary{
		PID:      123,
		ExecPath: "/bin/bash",
		Argv:     []string{"bash", "-c", "echo sk_csensor_secret"},
		Ancestors: []jobevent.AncestorProcess{
			{ExecPath: "/usr/bin/node", Argv: []string{"node", "postinstall", "password=raw"}},
		},
	}

	got := logProcessSummary(process)
	if got.Pid != 123 || got.ExecPath != "/bin/bash" {
		t.Fatalf("process identity mismatch: %+v", got)
	}
	if !reflect.DeepEqual(got.Argv, process.Argv) {
		t.Fatalf("argv redacted or changed: got %+v, want %+v", got.Argv, process.Argv)
	}
	if len(got.Ancestors) != 1 || !reflect.DeepEqual(got.Ancestors[0].Argv, process.Ancestors[0].Argv) {
		t.Fatalf("ancestor argv redacted or changed: %+v", got.Ancestors)
	}
}
