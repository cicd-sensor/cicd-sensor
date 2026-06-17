package kerneltracker

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

func TestHandleFileOpen_EmitsPayloadAndTruncatedTag(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "/bin/cat", nil, 0)

	effects := handleEngineInput(state, fileOpenSample{
		Identity:      identity,
		CgroupID:      42,
		TsNs:          17,
		Path:          "/tmp/very-long-path",
		Flags:         0x241,
		IsWrite:       true,
		IsRead:        true,
		PathTruncated: true,
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	if emit.Record.EventType != jobevent.FileOpen {
		t.Fatalf("kind = %q, want %q", emit.Record.EventType, jobevent.FileOpen)
	}
	if got, _ := emit.Record.Payload["path"].(string); got != "/tmp/very-long-path" {
		t.Fatalf("payload[path] = %q, want /tmp/very-long-path", got)
	}
	if got, _ := emit.Record.Payload["flags"].(int); got != 0x241 {
		t.Fatalf("payload[flags] = %#x, want %#x", got, 0x241)
	}
	if got, _ := emit.Record.Payload["is_write"].(bool); !got {
		t.Fatalf("payload[is_write] = false, want true")
	}
	if got, _ := emit.Record.Payload["is_read"].(bool); !got {
		t.Fatalf("payload[is_read] = false, want true")
	}
	if got := emit.Record.Tags["truncated"]; got != "path" {
		t.Fatalf("truncated tag = %q, want path", got)
	}

	assertPayloadKeys(t, emit.Record.Payload, fileOpenPayloadPath, fileOpenPayloadFlags, fileOpenPayloadIsWrite, fileOpenPayloadIsRead)
	payload, ok := fileOpenPayloadFromRecord(emit.Record)
	if !ok {
		t.Fatal("fileOpenPayloadFromRecord() ok = false, want true")
	}
	if payload != (fileOpenRecordPayload{Path: "/tmp/very-long-path", IsRead: true, IsWrite: true, Flags: 0x241}) {
		t.Fatalf("fileOpenPayloadFromRecord() = %#v", payload)
	}
	if _, ok := fileOpenDedupKeyForRecord(emit.Record); ok {
		t.Fatal("truncated file_open must not be eligible for dedup")
	}
}

func TestHandleFileOpen_PayloadRoundTripsToDedupKey(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "/bin/cat", nil, 0)

	effects := handleEngineInput(state, fileOpenSample{
		Identity: identity,
		CgroupID: 42,
		TsNs:     17,
		Path:     "/tmp/visible-path",
		Flags:    0x241,
		IsWrite:  true,
		IsRead:   true,
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	assertPayloadKeys(t, emit.Record.Payload, fileOpenPayloadPath, fileOpenPayloadFlags, fileOpenPayloadIsWrite, fileOpenPayloadIsRead)
	payload, ok := fileOpenPayloadFromRecord(emit.Record)
	if !ok {
		t.Fatal("fileOpenPayloadFromRecord() ok = false, want true")
	}
	if payload != (fileOpenRecordPayload{Path: "/tmp/visible-path", IsRead: true, IsWrite: true, Flags: 0x241}) {
		t.Fatalf("fileOpenPayloadFromRecord() = %#v", payload)
	}
	if _, ok := fileOpenDedupKeyForRecord(emit.Record); !ok {
		t.Fatal("fileOpenDedupKeyForRecord() ok = false, want true")
	}
}

func TestHandleFileRemove_EmitsPayload(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "/bin/rm", nil, 0)

	effects := handleEngineInput(state, fileRemoveSample{
		Identity: identity,
		CgroupID: 42,
		TsNs:     17,
		Path:     "/etc/shadow",
		IsFolder: false,
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	if emit.Record.EventType != jobevent.FileRemove {
		t.Fatalf("kind = %q, want %q", emit.Record.EventType, jobevent.FileRemove)
	}
	if got, _ := emit.Record.Payload["path"].(string); got != "/etc/shadow" {
		t.Fatalf("payload[path] = %q, want /etc/shadow", got)
	}
	if got, _ := emit.Record.Payload["is_folder"].(bool); got {
		t.Fatalf("payload[is_folder] = %v, want false", got)
	}
}

func TestHandleFileRemove_EmitsTruncatedTag(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "/bin/rm", nil, 0)

	effects := handleEngineInput(state, fileRemoveSample{
		Identity:      identity,
		CgroupID:      42,
		Path:          "/tmp/truncated",
		PathTruncated: true,
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	if got := emit.Record.Tags["truncated"]; got != "path" {
		t.Fatalf("truncated tag = %q, want path", got)
	}
}

func TestHandleFileMove_EmitsBothPaths(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "", nil, 0)

	effects := handleEngineInput(state, fileMoveSample{
		Identity:      identity,
		CgroupID:      42,
		FromPath:      "/tmp/payload.bin",
		ToPath:        "/run/init",
		FromTruncated: true,
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	if got, _ := emit.Record.Payload["from_path"].(string); got != "/tmp/payload.bin" {
		t.Fatalf("payload[from_path] = %q", got)
	}
	if got, _ := emit.Record.Payload["to_path"].(string); got != "/run/init" {
		t.Fatalf("payload[to_path] = %q", got)
	}
	if got := emit.Record.Tags["truncated"]; got != "path" {
		t.Fatalf("truncated tag = %q, want %q", got, "path")
	}
}

func TestHandleFileLink_HardlinkAbsolute(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "", nil, 0)

	effects := handleEngineInput(state, fileLinkSample{
		Identity:     identity,
		CgroupID:     42,
		CreatedPath:  "/tmp/copy",
		ExistingPath: "/etc/shadow",
		IsHardlink:   true,
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	if got, _ := emit.Record.Payload["existing_path"].(string); got != "/etc/shadow" {
		t.Fatalf("payload[existing_path] = %q, want /etc/shadow", got)
	}
	if got, _ := emit.Record.Payload["is_hardlink"].(bool); !got {
		t.Fatalf("payload[is_hardlink] = false, want true")
	}
}

func TestHandleFileLink_SymlinkRelativeResolved(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "", nil, 0)

	cases := []struct {
		name         string
		createdPath  string
		rawExisting  string
		wantExisting string
	}{
		{
			name:         "absolute_existing_passes_through",
			createdPath:  "/usr/local/bin/curl",
			rawExisting:  "/etc/shadow",
			wantExisting: "/etc/shadow",
		},
		{
			name:         "relative_existing_resolved_against_created_dirname",
			createdPath:  "/usr/local/bin/curl",
			rawExisting:  "../../tmp/wrap",
			wantExisting: "/usr/tmp/wrap",
		},
		{
			name:         "sibling_relative",
			createdPath:  "/etc/foo",
			rawExisting:  "bar",
			wantExisting: "/etc/bar",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			effects := handleEngineInput(state, fileLinkSample{
				Identity:     identity,
				CgroupID:     42,
				CreatedPath:  tc.createdPath,
				ExistingPath: tc.rawExisting,
				IsSymlink:    true,
			})

			emit, ok := singleEmitEventRecordEffect(effects)
			if !ok {
				t.Fatalf("effects = %#v, want single emitEventRecord", effects)
			}
			got, _ := emit.Record.Payload["existing_path"].(string)
			if got != tc.wantExisting {
				t.Fatalf("payload[existing_path] = %q, want %q", got, tc.wantExisting)
			}
			if v, _ := emit.Record.Payload["is_symlink"].(bool); !v {
				t.Fatalf("payload[is_symlink] = false, want true")
			}
		})
	}
}

func assertPayloadKeys(t *testing.T, payload map[string]any, keys ...string) {
	t.Helper()

	if len(payload) != len(keys) {
		t.Fatalf("payload keys = %v, want exactly %v", payload, keys)
	}
	for _, key := range keys {
		if _, ok := payload[key]; !ok {
			t.Fatalf("payload missing key %q in %v", key, payload)
		}
	}
}
