package celengine

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestEnvCompileAndEval(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	tests := []struct {
		name      string
		eventType jobevent.Type
		source    string
		input     CELInputEvent
		lists     map[string][]string
		wantMatch bool
	}{
		{
			name:      "list_field_access_matches",
			eventType: jobevent.ProcessExec,
			source:    `list.shell_binaries.exists(b, process.exec_path.endsWith(b))`,
			input:     CELInputEvent{Process: CELProcess{ExecPath: "/bin/bash"}},
			lists:     map[string][]string{"shell_binaries": {"/bash", "/sh"}},
			wantMatch: true,
		},
		{
			name:      "exists_over_argv_matches",
			eventType: jobevent.ProcessExec,
			source:    `process.argv.exists(arg, arg.contains("--token"))`,
			input:     CELInputEvent{Process: CELProcess{ExecPath: "/usr/bin/curl", Argv: []string{"curl", "--token=abc"}}},
			wantMatch: true,
		},
		{
			name:      "uppercase_exec_path_literal_matches_normalized_input",
			eventType: jobevent.ProcessExec,
			source:    `process.exec_path.endsWith("/BASH")`,
			input:     CELInputEvent{Process: CELProcess{ExecPath: "/bin/bash"}},
			wantMatch: true,
		},
		{
			name:      "uppercase_argv_literal_matches_normalized_input",
			eventType: jobevent.ProcessExec,
			source:    `process.argv.exists(arg, arg.contains("TOKEN"))`,
			input:     CELInputEvent{Process: CELProcess{ExecPath: "/usr/bin/npm", Argv: []string{"npm", "--token=abc"}}},
			wantMatch: true,
		},
		{
			name:      "logical_operators_match",
			eventType: jobevent.ProcessExec,
			source:    `process.exec_path != "/usr/bin/bash" && (process.exec_path == "/usr/bin/curl" || !process.argv.exists(arg, arg == "--quiet"))`,
			input:     CELInputEvent{Process: CELProcess{ExecPath: "/usr/bin/curl", Argv: []string{"curl", "--token=abc"}}},
			wantMatch: true,
		},
		{
			name:      "ancestor exec_path match",
			eventType: jobevent.ProcessExec,
			source:    `process.ancestors.exists(a, a.exec_path.endsWith("/curl"))`,
			input: CELInputEvent{Process: CELProcess{
				ExecPath:  "/bin/sh",
				Ancestors: []CELAncestor{{ExecPath: "/usr/bin/curl"}},
			}},
			wantMatch: true,
		},
		{
			name:      "ancestor argv match (lineage-aware rule)",
			eventType: jobevent.ProcessExec,
			source:    `process.ancestors.exists(a, a.exec_path.endsWith("/bash") && a.argv.exists(arg, arg == "-c"))`,
			input: CELInputEvent{Process: CELProcess{
				ExecPath:  "/usr/bin/python",
				Ancestors: []CELAncestor{{ExecPath: "/bin/bash", Argv: []string{"bash", "-c", "python -m foo"}}},
			}},
			wantMatch: true,
		},
		{
			name:      "ancestor normalized case",
			eventType: jobevent.ProcessExec,
			source:    `process.ancestors.exists(a, a.exec_path == "/bin/bash")`,
			input: CELInputEvent{Process: CELProcess{
				ExecPath:  "/usr/bin/python",
				Ancestors: []CELAncestor{{ExecPath: rule.NormalizeString("/BIN/BASH")}},
			}},
			wantMatch: true,
		},
		{
			name:      "in_ip_range_matches_ipv4",
			eventType: jobevent.NetworkConnect,
			source:    `inIpRange(remote_ip, "10.0.0.0/8")`,
			input:     CELInputEvent{RemoteIP: "10.1.2.3"},
			wantMatch: true,
		},
		{
			name:      "in_ip_range_matches_ipv6",
			eventType: jobevent.NetworkConnect,
			source:    `inIpRange(remote_ip, "2001:db8::/32")`,
			input:     CELInputEvent{RemoteIP: "2001:db8::1"},
			wantMatch: true,
		},
		{
			name:      "normalization_is_case_insensitive",
			eventType: jobevent.NetworkConnect,
			source:    `remote_ip == "EXAMPLE.COM"`,
			input:     CELInputEvent{RemoteIP: "example.com"},
			wantMatch: true,
		},
		{
			name:      "normalization_handles_unicode_nfc",
			eventType: jobevent.ProcessExec,
			source:    `process.exec_path == "/USR/BIN/CAFÉ"`,
			input:     CELInputEvent{Process: CELProcess{ExecPath: "/usr/bin/café"}},
			wantMatch: true,
		},
		{
			name:      "network_endswith_and_protocol_match",
			eventType: jobevent.NetworkConnect,
			source:    `protocol == "tcp" && remote_ip.endsWith("npmjs.org")`,
			input:     CELInputEvent{RemoteIP: "registry.npmjs.org", Protocol: "tcp"},
			wantMatch: true,
		},
		{
			name:      "family_ipv6_matches",
			eventType: jobevent.NetworkConnect,
			source:    `family == "ipv6"`,
			input:     CELInputEvent{Family: "ipv6"},
			wantMatch: true,
		},
		{
			// Locks the dual-stack normalization contract: an AF_INET6
			// socket connecting to an IPv4 destination via IPv4-mapped
			// IPv6 surfaces as remote_ip in dotted-quad form + family
			// "ipv4". A rule that filters on family == "ipv4" and
			// matches a /8 CIDR fires for both connect4 and connect6
			// hooks once normalization stamps "ipv4" consistently.
			name:      "family_ipv4_with_cidr_dual_stack",
			eventType: jobevent.NetworkConnect,
			source:    `family == "ipv4" && inIpRange(remote_ip, "10.0.0.0/8")`,
			input:     CELInputEvent{RemoteIP: "10.1.2.3", Family: "ipv4"},
			wantMatch: true,
		},
		{
			name:      "file_open_path_endswith_matches",
			eventType: jobevent.FileOpen,
			source:    `path.endsWith(".env")`,
			input:     CELInputEvent{Path: "/workspace/.env"},
			wantMatch: true,
		},
		{
			name:      "file_open_can_reference_process",
			eventType: jobevent.FileOpen,
			source:    `process.exec_path.endsWith("/cat") && path.endsWith(".env")`,
			input: CELInputEvent{
				Process: CELProcess{ExecPath: "/bin/cat"},
				Path:    "/workspace/.env",
			},
			wantMatch: true,
		},
		{
			name:      "hostname_is_not_ip_range",
			eventType: jobevent.NetworkConnect,
			source:    `inIpRange(remote_ip, "10.0.0.0/8")`,
			input:     CELInputEvent{RemoteIP: "registry.npmjs.org"},
			wantMatch: false,
		},
		{
			name:      "is_memfd_true",
			eventType: jobevent.ProcessExec,
			source:    `is_memfd`,
			input:     CELInputEvent{IsMemfd: true},
			wantMatch: true,
		},
		{
			name:      "is_memfd_false",
			eventType: jobevent.ProcessExec,
			source:    `is_memfd`,
			input:     CELInputEvent{IsMemfd: false},
			wantMatch: false,
		},
		{
			name:      "is_memfd_combined_with_process",
			eventType: jobevent.ProcessExec,
			source:    `is_memfd && process.exec_path.startsWith("/dev/fd/")`,
			input: CELInputEvent{
				IsMemfd: true,
				Process: CELProcess{ExecPath: "/dev/fd/3"},
			},
			wantMatch: true,
		},
		{
			name:      "file_remove_unlink_secret",
			eventType: jobevent.FileRemove,
			source:    `!is_folder && path == "/etc/shadow"`,
			input:     CELInputEvent{Path: "/etc/shadow", IsFolder: false},
			wantMatch: true,
		},
		{
			name:      "file_remove_rmdir_skipped",
			eventType: jobevent.FileRemove,
			source:    `!is_folder && path == "/etc/shadow"`,
			input:     CELInputEvent{Path: "/etc/shadow", IsFolder: true},
			wantMatch: false,
		},
		{
			name:      "file_move_renames_into_run",
			eventType: jobevent.FileMove,
			source:    `from_path.startsWith("/tmp/") && to_path.startsWith("/run/")`,
			input: CELInputEvent{
				FromPath: "/tmp/payload.bin",
				ToPath:   "/run/initrd/init",
			},
			wantMatch: true,
		},
		{
			name:      "file_link_symlink_into_local_bin",
			eventType: jobevent.FileLink,
			source:    `is_symlink && created_path.startsWith("/usr/local/bin/") && existing_path.startsWith("/tmp/")`,
			input: CELInputEvent{
				CreatedPath:  "/usr/local/bin/curl",
				ExistingPath: "/tmp/wrapper",
				IsSymlink:    true,
			},
			wantMatch: true,
		},
		{
			name:      "file_link_hardlink_to_shadow",
			eventType: jobevent.FileLink,
			source:    `is_hardlink && existing_path == "/etc/shadow"`,
			input: CELInputEvent{
				CreatedPath:  "/tmp/copy",
				ExistingPath: "/etc/shadow",
				IsHardlink:   true,
			},
			wantMatch: true,
		},
		{
			name:      "domain_endswith_match",
			eventType: jobevent.Domain,
			source:    `domain.endsWith(".evil.example.com")`,
			input:     CELInputEvent{Domain: "exfil.evil.example.com", Source: "dns"},
			wantMatch: true,
		},
		{
			name:      "domain_source_filter",
			eventType: jobevent.Domain,
			source:    `source == "dns" && domain == "example.com"`,
			input:     CELInputEvent{Domain: "example.com", Source: "dns"},
			wantMatch: true,
		},
		{
			name:      "domain_combined_with_process",
			eventType: jobevent.Domain,
			source:    `domain == "registry.npmjs.org" && process.exec_path.endsWith("/curl")`,
			input: CELInputEvent{
				Domain:  "registry.npmjs.org",
				Source:  "dns",
				Process: CELProcess{ExecPath: "/usr/bin/curl"},
			},
			wantMatch: true,
		},
		{
			name:      "domain_no_match",
			eventType: jobevent.Domain,
			source:    `domain.endsWith(".evil.example.com")`,
			input:     CELInputEvent{Domain: "example.com", Source: "dns"},
			wantMatch: false,
		},
		{
			name:      "unix_socket_path_filesystem_match",
			eventType: jobevent.UnixSocketConnect,
			source:    `path == "/var/run/docker.sock"`,
			input:     CELInputEvent{Path: "/var/run/docker.sock", SocketType: "stream"},
			wantMatch: true,
		},
		{
			name:      "unix_socket_abstract_at_prefix_match",
			eventType: jobevent.UnixSocketConnect,
			source:    `is_abstract && path.startsWith("@dbus-")`,
			input:     CELInputEvent{Path: "@dbus-7", SocketType: "dgram", IsAbstract: true},
			wantMatch: true,
		},
		{
			name:      "unix_socket_combined_with_process",
			eventType: jobevent.UnixSocketConnect,
			source:    `socket_type == "stream" && process.exec_path.endsWith("/docker")`,
			input: CELInputEvent{
				Path:       "/var/run/docker.sock",
				SocketType: "stream",
				Process:    CELProcess{ExecPath: "/usr/bin/docker"},
			},
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prog, err := env.Compile("rule-1", tt.eventType, tt.source, tt.lists)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			staticActivation, err := NewListActivation(rule.NormalizePredefinedLists(tt.lists))
			if err != nil {
				t.Fatalf("new list activation: %v", err)
			}
			matched, err := prog.EvalActivation(NewEventActivation(tt.input).WithParent(staticActivation))
			if err != nil {
				t.Fatalf("eval activation: %v", err)
			}
			if matched != tt.wantMatch {
				t.Fatalf("matched: got %v, want %v", matched, tt.wantMatch)
			}
		})
	}
}

func TestEnvForKindRejectsUnsupportedKind(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	if _, err := env.EnvForType(jobevent.Type("unknown")); err == nil {
		t.Fatal("expected unsupported event type error")
	}
}
