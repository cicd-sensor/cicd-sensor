package kerneltracker

import (
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"testing"
)

func TestHandleUnixSocketConnect(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	cases := []struct {
		name              string
		sunPath           []byte
		isAbstract        bool
		socketType        uint8
		cwd               string
		cwdTruncated      bool
		cwdUnavailable    bool
		sunPathTruncated  bool
		wantPath          string
		wantSocketType    string
		wantTagTruncated  bool
		wantTagCwdUnavail bool
	}{
		{
			name:           "absolute_filesystem_stream_verbatim",
			sunPath:        []byte("/run/systemd/journal/socket"),
			socketType:     1,
			wantPath:       "/run/systemd/journal/socket",
			wantSocketType: "stream",
		},
		{
			name:           "absolute_keeps_symlink_alias",
			sunPath:        []byte("/var/run/docker.sock"),
			socketType:     1,
			wantPath:       "/var/run/docker.sock",
			wantSocketType: "stream",
		},
		{
			name:           "abstract_dgram_at_prefix",
			sunPath:        append([]byte{0x00}, []byte("dbus-7")...),
			isAbstract:     true,
			socketType:     2,
			wantPath:       "@dbus-7",
			wantSocketType: "dgram",
		},
		{
			name:           "seqpacket_translation",
			sunPath:        []byte("/run/foo.sock"),
			socketType:     5,
			wantPath:       "/run/foo.sock",
			wantSocketType: "seqpacket",
		},
		{
			name:           "unknown_socket_type",
			sunPath:        []byte("/run/foo.sock"),
			socketType:     99,
			wantPath:       "/run/foo.sock",
			wantSocketType: "unknown",
		},
		{
			name:           "relative_joined_with_cwd",
			sunPath:        []byte("./docker.sock"),
			socketType:     1,
			cwd:            "/run",
			wantPath:       "/run/docker.sock",
			wantSocketType: "stream",
		},
		{
			name:           "relative_dot_dot_collapsed",
			sunPath:        []byte("../etc/passwd.sock"),
			socketType:     1,
			cwd:            "/var/run",
			wantPath:       "/var/etc/passwd.sock",
			wantSocketType: "stream",
		},
		{
			name:           "relative_dot_segment_collapsed",
			sunPath:        []byte("./foo/./bar.sock"),
			socketType:     1,
			cwd:            "/run",
			wantPath:       "/run/foo/bar.sock",
			wantSocketType: "stream",
		},
		{
			name:           "relative_bare_filename",
			sunPath:        []byte("docker.sock"),
			socketType:     1,
			cwd:            "/run",
			wantPath:       "/run/docker.sock",
			wantSocketType: "stream",
		},
		{
			name:              "relative_cwd_unavailable_falls_back_to_verbatim",
			sunPath:           []byte("./docker.sock"),
			socketType:        1,
			cwdUnavailable:    true,
			wantPath:          "./docker.sock",
			wantSocketType:    "stream",
			wantTagCwdUnavail: true,
		},
		{
			name:             "sun_path_truncation_tag",
			sunPath:          []byte("/run/very/long/path"),
			socketType:       1,
			sunPathTruncated: true,
			wantPath:         "/run/very/long/path",
			wantSocketType:   "stream",
			wantTagTruncated: true,
		},
		{
			name:             "cwd_truncation_tag",
			sunPath:          []byte("./docker.sock"),
			socketType:       1,
			cwd:              "/run",
			cwdTruncated:     true,
			wantPath:         "/run/docker.sock",
			wantSocketType:   "stream",
			wantTagTruncated: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := destinationTrackedState(jobID, 42)
			state.recordExec(jobID, identity, "/usr/bin/dbus-send", nil, 0)

			effects := handleEngineInput(state, unixSocketConnectSample{
				Identity:         identity,
				CgroupID:         42,
				TsNs:             17,
				SunPath:          tc.sunPath,
				SunPathLen:       uint32(len(tc.sunPath)),
				SunPathTruncated: tc.sunPathTruncated,
				Cwd:              tc.cwd,
				CwdTruncated:     tc.cwdTruncated,
				CwdUnavailable:   tc.cwdUnavailable,
				SocketType:       tc.socketType,
				IsAbstract:       tc.isAbstract,
			})

			emit, ok := singleEmitEventRecordEffect(effects)
			if !ok {
				t.Fatalf("effects = %#v, want single emitEventRecord", effects)
			}
			if emit.Record.EventType != jobevent.UnixSocketConnect {
				t.Fatalf("kind = %q, want %q", emit.Record.EventType, jobevent.UnixSocketConnect)
			}
			if got, _ := emit.Record.Payload["path"].(string); got != tc.wantPath {
				t.Fatalf("payload[path] = %q, want %q", got, tc.wantPath)
			}
			if got, _ := emit.Record.Payload["socket_type"].(string); got != tc.wantSocketType {
				t.Fatalf("payload[socket_type] = %q, want %q", got, tc.wantSocketType)
			}
			if got, _ := emit.Record.Payload["is_abstract"].(bool); got != tc.isAbstract {
				t.Fatalf("payload[is_abstract] = %v, want %v", got, tc.isAbstract)
			}
			if tag := emit.Record.Tags["truncated"]; (tag == "path") != tc.wantTagTruncated {
				t.Fatalf("tags[truncated] = %q, want path=%v", tag, tc.wantTagTruncated)
			}
			if tag := emit.Record.Tags["cwd_unavailable"]; (tag == "true") != tc.wantTagCwdUnavail {
				t.Fatalf("tags[cwd_unavailable] = %q, want true=%v", tag, tc.wantTagCwdUnavail)
			}
		})
	}
}
