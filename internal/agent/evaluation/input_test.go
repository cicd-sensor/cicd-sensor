package evaluation

import (
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/traits"
)

func TestCELInputEventFromRecordNormalizesProcessAndPayload(t *testing.T) {
	t.Parallel()

	input := celInputEventFromRecord(jobevent.EventRecord{
		EventType: jobevent.NetworkConnect,
		Payload: map[string]any{
			"remote_ip":   "EXAMPLE.COM",
			"remote_port": 443,
			"protocol":    "TCP",
		},
		Process: jobevent.ProcessSummary{
			ExecPath: "/USR/BIN/CAFÉ",
			Argv:     []string{"CAFÉ", "--FLAG"},
			Ancestors: []jobevent.AncestorProcess{
				{ExecPath: "/BIN/BASH", Argv: []string{"BASH", "-C", "RUN"}},
				{ExecPath: "/SBIN/SYSTEMD"},
			},
		},
	})

	if input.Process.ExecPath != "/usr/bin/café" {
		t.Fatalf("process.exec_path: got %q, want %q", input.Process.ExecPath, "/usr/bin/café")
	}
	if input.RemoteIP != "example.com" {
		t.Fatalf("remote_ip: got %q, want %q", input.RemoteIP, "example.com")
	}
	if input.RemotePort != 443 {
		t.Fatalf("remote_port: got %d, want %d", input.RemotePort, 443)
	}
	if input.Protocol != "tcp" {
		t.Fatalf("protocol: got %q, want %q", input.Protocol, "tcp")
	}
	if joined := strings.Join(input.Process.Argv, ","); joined != "café,--flag" {
		t.Fatalf("process.argv: got %q, want %q", joined, "café,--flag")
	}
	if len(input.Process.Ancestors) != 2 {
		t.Fatalf("ancestors length: got %d, want 2", len(input.Process.Ancestors))
	}
	if got := input.Process.Ancestors[0].ExecPath; got != "/bin/bash" {
		t.Fatalf("ancestors[0].exec_path: got %q, want %q", got, "/bin/bash")
	}
	if joined := strings.Join(input.Process.Ancestors[0].Argv, ","); joined != "bash,-c,run" {
		t.Fatalf("ancestors[0].argv: got %q, want %q", joined, "bash,-c,run")
	}
	if got := input.Process.Ancestors[1].ExecPath; got != "/sbin/systemd" {
		t.Fatalf("ancestors[1].exec_path: got %q, want %q", got, "/sbin/systemd")
	}
}

func TestCELInputEventFromRecordFileMutationTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		event     jobevent.EventRecord
		assertion func(t *testing.T, input celengine.CELInputEvent)
	}{
		{
			name: "file_remove_unlink",
			event: jobevent.EventRecord{
				EventType: jobevent.FileRemove,
				Payload: map[string]any{
					"path":      "/ETC/SHADOW",
					"is_folder": false,
				},
			},
			assertion: func(t *testing.T, input celengine.CELInputEvent) {
				if input.Path != "/etc/shadow" {
					t.Fatalf("path: got %q, want /etc/shadow", input.Path)
				}
				if input.IsFolder {
					t.Fatalf("is_folder: got true, want false")
				}
			},
		},
		{
			name: "file_remove_rmdir",
			event: jobevent.EventRecord{
				EventType: jobevent.FileRemove,
				Payload: map[string]any{
					"path":      "/var/log/journal",
					"is_folder": true,
				},
			},
			assertion: func(t *testing.T, input celengine.CELInputEvent) {
				if input.Path != "/var/log/journal" {
					t.Fatalf("path: got %q", input.Path)
				}
				if !input.IsFolder {
					t.Fatalf("is_folder: got false, want true")
				}
			},
		},
		{
			name: "file_move_normalizes_paths",
			event: jobevent.EventRecord{
				EventType: jobevent.FileMove,
				Payload: map[string]any{
					"from_path": "/TMP/PAYLOAD.BIN",
					"to_path":   "/RUN/INIT",
				},
			},
			assertion: func(t *testing.T, input celengine.CELInputEvent) {
				if input.FromPath != "/tmp/payload.bin" {
					t.Fatalf("from_path: got %q", input.FromPath)
				}
				if input.ToPath != "/run/init" {
					t.Fatalf("to_path: got %q", input.ToPath)
				}
			},
		},
		{
			name: "file_link_hardlink",
			event: jobevent.EventRecord{
				EventType: jobevent.FileLink,
				Payload: map[string]any{
					"created_path":  "/tmp/copy",
					"existing_path": "/etc/shadow",
					"is_hardlink":   true,
					"is_symlink":    false,
				},
			},
			assertion: func(t *testing.T, input celengine.CELInputEvent) {
				if input.CreatedPath != "/tmp/copy" {
					t.Fatalf("created_path: got %q", input.CreatedPath)
				}
				if input.ExistingPath != "/etc/shadow" {
					t.Fatalf("existing_path: got %q", input.ExistingPath)
				}
				if !input.IsHardlink || input.IsSymlink {
					t.Fatalf("flags: hardlink=%v symlink=%v, want true/false",
						input.IsHardlink, input.IsSymlink)
				}
			},
		},
		{
			name: "file_link_symlink",
			event: jobevent.EventRecord{
				EventType: jobevent.FileLink,
				Payload: map[string]any{
					"created_path":  "/usr/local/bin/curl",
					"existing_path": "/usr/tmp/wrap", // already absolutized by handler
					"is_hardlink":   false,
					"is_symlink":    true,
				},
			},
			assertion: func(t *testing.T, input celengine.CELInputEvent) {
				if input.CreatedPath != "/usr/local/bin/curl" {
					t.Fatalf("created_path: got %q", input.CreatedPath)
				}
				if input.ExistingPath != "/usr/tmp/wrap" {
					t.Fatalf("existing_path: got %q", input.ExistingPath)
				}
				if input.IsHardlink || !input.IsSymlink {
					t.Fatalf("flags: hardlink=%v symlink=%v, want false/true",
						input.IsHardlink, input.IsSymlink)
				}
			},
		},
		{
			name: "file_remove_missing_payload_is_zero",
			event: jobevent.EventRecord{
				EventType: jobevent.FileRemove,
				Payload:   nil,
			},
			assertion: func(t *testing.T, input celengine.CELInputEvent) {
				if input.Path != "" {
					t.Fatalf("path: got %q, want empty", input.Path)
				}
				if input.IsFolder {
					t.Fatalf("is_folder: got true, want false")
				}
			},
		},
		{
			name: "file_link_payload_wrong_types_falls_back_to_zero",
			event: jobevent.EventRecord{
				EventType: jobevent.FileLink,
				Payload: map[string]any{
					"created_path": 42,    // wrong type
					"is_hardlink":  "yes", // wrong type
				},
			},
			assertion: func(t *testing.T, input celengine.CELInputEvent) {
				if input.CreatedPath != "" {
					t.Fatalf("created_path: got %q, want empty", input.CreatedPath)
				}
				if input.IsHardlink {
					t.Fatalf("is_hardlink: got true, want false")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := celInputEventFromRecord(tt.event)
			tt.assertion(t, input)
		})
	}
}

func TestCELInputEventFromRecordEventTypePayloads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		event     jobevent.EventRecord
		assertion func(t *testing.T, input celengine.CELInputEvent)
	}{
		{
			name: "process_exec_memfd",
			event: jobevent.EventRecord{
				EventType: jobevent.ProcessExec,
				Payload: map[string]any{
					"is_memfd": true,
				},
			},
			assertion: func(t *testing.T, input celengine.CELInputEvent) {
				if !input.IsMemfd {
					t.Fatalf("is_memfd: got false, want true")
				}
			},
		},
		{
			name: "file_open_flags_and_access",
			event: jobevent.EventRecord{
				EventType: jobevent.FileOpen,
				Payload: map[string]any{
					"path":     "/TMP/SECRET.ENV",
					"is_write": true,
					"is_read":  true,
					"flags":    int32(66),
				},
			},
			assertion: func(t *testing.T, input celengine.CELInputEvent) {
				if input.Path != "/tmp/secret.env" {
					t.Fatalf("path: got %q, want /tmp/secret.env", input.Path)
				}
				if !input.IsWrite || !input.IsRead {
					t.Fatalf("access flags: is_write=%v is_read=%v, want true/true", input.IsWrite, input.IsRead)
				}
				if input.Flags != 66 {
					t.Fatalf("flags: got %d, want 66", input.Flags)
				}
			},
		},
		{
			name: "domain_query_and_source",
			event: jobevent.EventRecord{
				EventType: jobevent.Domain,
				Payload: map[string]any{
					"domain": "Registry.NPMJS.Org",
					"source": "DNS",
				},
			},
			assertion: func(t *testing.T, input celengine.CELInputEvent) {
				if input.Domain != "registry.npmjs.org" {
					t.Fatalf("domain: got %q, want registry.npmjs.org", input.Domain)
				}
				if input.Source != "dns" {
					t.Fatalf("source: got %q, want dns", input.Source)
				}
			},
		},
		{
			name: "unix_socket_connect",
			event: jobevent.EventRecord{
				EventType: jobevent.UnixSocketConnect,
				Payload: map[string]any{
					"path":        "@DBUS-7",
					"socket_type": "STREAM",
					"is_abstract": true,
				},
			},
			assertion: func(t *testing.T, input celengine.CELInputEvent) {
				if input.Path != "@dbus-7" {
					t.Fatalf("path: got %q, want @dbus-7", input.Path)
				}
				if input.SocketType != "stream" {
					t.Fatalf("socket_type: got %q, want stream", input.SocketType)
				}
				if !input.IsAbstract {
					t.Fatalf("is_abstract: got false, want true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := celInputEventFromRecord(tt.event)
			tt.assertion(t, input)
		})
	}
}

func TestCELInputEventFromRecordReturnsEmptyAncestorsWhenMissing(t *testing.T) {
	t.Parallel()

	input := celInputEventFromRecord(jobevent.EventRecord{
		EventType: jobevent.ProcessExec,
		Process: jobevent.ProcessSummary{
			ExecPath: "/usr/bin/echo",
		},
	})

	if input.Process.Ancestors != nil {
		t.Fatalf("ancestors: got %#v, want nil", input.Process.Ancestors)
	}
}

func TestEventActivationResolvesParentList(t *testing.T) {
	t.Parallel()

	parent, err := celengine.NewListActivation(rule.PredefinedLists{
		"shells": {"/bash"},
	})
	if err != nil {
		t.Fatalf("new list activation: %v", err)
	}

	activation := celengine.NewEventActivation(celengine.CELInputEvent{
		Process: celengine.CELProcess{ExecPath: "/bin/bash"},
	}).WithParent(parent)

	if got, ok := activation.ResolveName("process"); !ok || got.(*celengine.CELProcess).ExecPath != "/bin/bash" {
		t.Fatalf("process: got (%#v, %v), want local *celengine.CELProcess", got, ok)
	}
	if got, ok := activation.ResolveName("list"); !ok {
		t.Fatal("list: got unresolved, want parent list")
	} else if _, ok := got.(map[string]any); !ok {
		t.Fatalf("list: got %T, want map[string]any", got)
	}
	if got := activation.Parent(); got == nil {
		t.Fatal("parent: got nil, want list activation")
	}
	if got, ok := activation.ResolveName("missing"); ok || got != nil {
		t.Fatalf("missing: got (%#v, %v), want nil/false", got, ok)
	}
}

func TestNewListActivationClonesListValues(t *testing.T) {
	t.Parallel()

	lists := rule.PredefinedLists{
		"shells": {"/bash"},
	}
	activation, err := celengine.NewListActivation(lists)
	if err != nil {
		t.Fatalf("new list activation: %v", err)
	}
	lists["shells"][0] = "/zsh"

	got, ok := activation.ResolveName("list")
	if !ok {
		t.Fatal("list: got unresolved, want activation")
	}
	gotLists, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("list: got %T, want map[string]any", got)
	}
	gotShells, ok := gotLists["shells"].(traits.Lister)
	if !ok {
		t.Fatalf("list.shells: got %T, want traits.Lister", gotLists["shells"])
	}
	if size := gotShells.Size().(types.Int); size != 1 {
		t.Fatalf("list.shells size: got %d, want 1", size)
	}
	if first := gotShells.Get(types.Int(0)).Value(); first != "/bash" {
		t.Fatalf("list.shells[0]: got %v, want cloned original value", first)
	}
}

func TestCELInputEventFromRecordPayloadTypeCoercion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		payload    map[string]any
		wantPort   int64
		wantFamily string
	}{
		{
			name: "json_number_float64_port",
			payload: map[string]any{
				"remote_port": float64(443),
				"family":      "IPV4",
			},
			wantPort:   443,
			wantFamily: "ipv4",
		},
		{
			name: "wrong_types_fall_back_to_zero",
			payload: map[string]any{
				"remote_port": "443",
				"family":      4,
			},
			wantPort:   0,
			wantFamily: "",
		},
		{
			name:       "missing_payload_is_zero",
			payload:    nil,
			wantPort:   0,
			wantFamily: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			input := celInputEventFromRecord(jobevent.EventRecord{
				EventType: jobevent.NetworkConnect,
				Payload:   tt.payload,
			})
			if input.RemotePort != tt.wantPort {
				t.Fatalf("remote_port: got %d, want %d", input.RemotePort, tt.wantPort)
			}
			if input.Family != tt.wantFamily {
				t.Fatalf("family: got %q, want %q", input.Family, tt.wantFamily)
			}
		})
	}
}
