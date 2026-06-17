package kerneltracker

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

func TestFileOpenPayloadFromRecord(t *testing.T) {
	t.Parallel()

	baseRecord := func() jobevent.EventRecord {
		return jobevent.EventRecord{
			EventType: jobevent.FileOpen,
			Payload: map[string]any{
				fileOpenPayloadPath:    "/workspace/secret.txt",
				fileOpenPayloadIsRead:  true,
				fileOpenPayloadIsWrite: false,
				fileOpenPayloadFlags:   0x241,
			},
		}
	}

	cases := []struct {
		name   string
		mutate func(jobevent.EventRecord) jobevent.EventRecord
		wantOK bool
		want   fileOpenRecordPayload
	}{
		{
			name:   "valid payload",
			wantOK: true,
			want: fileOpenRecordPayload{
				Path:    "/workspace/secret.txt",
				IsRead:  true,
				IsWrite: false,
				Flags:   0x241,
			},
		},
		{
			name: "non file open",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.EventType = jobevent.ProcessExec
				return record
			},
		},
		{
			name: "missing path",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				delete(record.Payload, fileOpenPayloadPath)
				return record
			},
		},
		{
			name: "wrong path type",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Payload[fileOpenPayloadPath] = 42
				return record
			},
		},
		{
			name: "missing read mode",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				delete(record.Payload, fileOpenPayloadIsRead)
				return record
			},
		},
		{
			name: "wrong read mode type",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Payload[fileOpenPayloadIsRead] = "true"
				return record
			},
		},
		{
			name: "missing write mode",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				delete(record.Payload, fileOpenPayloadIsWrite)
				return record
			},
		},
		{
			name: "wrong write mode type",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Payload[fileOpenPayloadIsWrite] = "false"
				return record
			},
		},
		{
			name: "missing flags",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				delete(record.Payload, fileOpenPayloadFlags)
				return record
			},
		},
		{
			name: "wrong flags type",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Payload[fileOpenPayloadFlags] = int32(0x241)
				return record
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			record := baseRecord()
			if tc.mutate != nil {
				record = tc.mutate(record)
			}

			got, ok := fileOpenPayloadFromRecord(record)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if got != tc.want {
				t.Fatalf("payload = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestFileOpenDedupKeyForRecord(t *testing.T) {
	t.Parallel()

	baseRecord := func() jobevent.EventRecord {
		return jobevent.EventRecord{
			EventType: jobevent.FileOpen,
			Process: jobevent.ProcessSummary{
				PID:           123,
				StartBoottime: 456,
				ExecPath:      "/usr/bin/cat",
			},
			Payload: map[string]any{
				fileOpenPayloadPath:    "/workspace/secret.txt",
				fileOpenPayloadIsRead:  true,
				fileOpenPayloadIsWrite: false,
				fileOpenPayloadFlags:   0,
			},
		}
	}
	wantKey := func(payload fileOpenRecordPayload) fileOpenDedupKey {
		return fileOpenDedupKey{
			pid:           123,
			startBoottime: 456,
			execPath:      "/usr/bin/cat",
			payload:       payload,
		}
	}
	basePayload := fileOpenRecordPayload{
		Path:    "/workspace/secret.txt",
		IsRead:  true,
		IsWrite: false,
		Flags:   0,
	}

	cases := []struct {
		name   string
		mutate func(jobevent.EventRecord) jobevent.EventRecord
		wantOK bool
		want   fileOpenDedupKey
	}{
		{
			name:   "valid read key",
			wantOK: true,
			want:   wantKey(basePayload),
		},
		{
			name: "path difference changes key",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Payload[fileOpenPayloadPath] = "/workspace/other.txt"
				return record
			},
			wantOK: true,
			want:   wantKey(fileOpenRecordPayload{Path: "/workspace/other.txt", IsRead: true, IsWrite: false, Flags: 0}),
		},
		{
			name: "process pid difference changes key",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Process.PID = 124
				return record
			},
			wantOK: true,
			want: fileOpenDedupKey{
				pid:           124,
				startBoottime: 456,
				execPath:      "/usr/bin/cat",
				payload:       basePayload,
			},
		},
		{
			name: "process start time difference changes key",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Process.StartBoottime = 789
				return record
			},
			wantOK: true,
			want: fileOpenDedupKey{
				pid:           123,
				startBoottime: 789,
				execPath:      "/usr/bin/cat",
				payload:       basePayload,
			},
		},
		{
			name: "exec path difference changes key",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Process.ExecPath = "/usr/bin/tar"
				return record
			},
			wantOK: true,
			want: fileOpenDedupKey{
				pid:           123,
				startBoottime: 456,
				execPath:      "/usr/bin/tar",
				payload:       basePayload,
			},
		},
		{
			name: "read write mode difference changes key",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Payload[fileOpenPayloadIsRead] = false
				record.Payload[fileOpenPayloadIsWrite] = true
				return record
			},
			wantOK: true,
			want:   wantKey(fileOpenRecordPayload{Path: "/workspace/secret.txt", IsRead: false, IsWrite: true, Flags: 0}),
		},
		{
			name: "flags difference changes key",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Payload[fileOpenPayloadFlags] = 0x241
				return record
			},
			wantOK: true,
			want:   wantKey(fileOpenRecordPayload{Path: "/workspace/secret.txt", IsRead: true, IsWrite: false, Flags: 0x241}),
		},
		{
			name: "non file open is not eligible",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.EventType = jobevent.ProcessExec
				return record
			},
		},
		{
			name: "truncated path is not eligible",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Tags = map[string]string{"truncated": "path"}
				return record
			},
		},
		{
			name: "empty path is not eligible",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Payload[fileOpenPayloadPath] = ""
				return record
			},
		},
		{
			name: "missing process pid is not eligible",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Process.PID = 0
				return record
			},
		},
		{
			name: "missing process start time is not eligible",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Process.StartBoottime = 0
				return record
			},
		},
		{
			name: "missing read mode is not eligible",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				delete(record.Payload, fileOpenPayloadIsRead)
				return record
			},
		},
		{
			name: "malformed write mode is not eligible",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Payload[fileOpenPayloadIsWrite] = "false"
				return record
			},
		},
		{
			name: "missing flags is not eligible",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				delete(record.Payload, fileOpenPayloadFlags)
				return record
			},
		},
		{
			name: "malformed flags is not eligible",
			mutate: func(record jobevent.EventRecord) jobevent.EventRecord {
				record.Payload[fileOpenPayloadFlags] = int32(0)
				return record
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			record := baseRecord()
			if tc.mutate != nil {
				record = tc.mutate(record)
			}

			got, ok := fileOpenDedupKeyForRecord(record)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if got != tc.want {
				t.Fatalf("key = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestFileOpenDedupState(t *testing.T) {
	t.Parallel()

	key := func(path string) fileOpenDedupKey {
		return fileOpenDedupKey{
			pid:           123,
			startBoottime: 456,
			execPath:      "/usr/bin/cat",
			payload: fileOpenRecordPayload{
				Path:   path,
				IsRead: true,
				Flags:  0,
			},
		}
	}

	cases := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "duplicate hit is visible after remember",
			run: func(t *testing.T) {
				state := newFileOpenDedupState(2)
				first := key("/tmp/a")

				if state.contains(first) {
					t.Fatal("key must not be present before remember")
				}
				state.remember(first)
				if !state.contains(first) {
					t.Fatal("key must be present after remember")
				}
			},
		},
		{
			name: "duplicate hit does not refresh fifo order",
			run: func(t *testing.T) {
				state := newFileOpenDedupState(2)
				first := key("/tmp/a")
				second := key("/tmp/b")
				third := key("/tmp/c")

				state.remember(first)
				state.remember(second)
				state.remember(first)
				state.remember(third)

				if state.contains(first) {
					t.Fatal("duplicate remember refreshed FIFO order; oldest key survived")
				}
				if !state.contains(second) || !state.contains(third) {
					t.Fatal("newer keys must survive FIFO eviction")
				}
			},
		},
		{
			name: "oldest inserted key is evicted at capacity",
			run: func(t *testing.T) {
				state := newFileOpenDedupState(2)
				first := key("/tmp/a")
				second := key("/tmp/b")
				third := key("/tmp/c")

				state.remember(first)
				state.remember(second)
				state.remember(third)

				if state.contains(first) {
					t.Fatal("oldest key survived capacity eviction")
				}
				if !state.contains(second) || !state.contains(third) {
					t.Fatal("newer keys must survive capacity eviction")
				}
			},
		},
		{
			name: "table size never exceeds limit",
			run: func(t *testing.T) {
				state := newFileOpenDedupState(2)
				state.remember(key("/tmp/a"))
				state.remember(key("/tmp/b"))
				state.remember(key("/tmp/c"))

				if got := len(state.seen); got != 2 {
					t.Fatalf("seen size = %d, want 2", got)
				}
				if got := len(state.order); got != 2 {
					t.Fatalf("order size = %d, want 2", got)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t)
		})
	}
}
