//go:build linux

package kernelio

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHTTPUprobeWorkerQueueAttachCandidate(t *testing.T) {
	t.Parallel()
	candidate := httpUprobeAttachCandidate{tgid: 4321, vmStart: 0x400000, vmEnd: 0x401000}

	t.Run("available queue records the attach candidate", func(t *testing.T) {
		t.Parallel()
		worker := &httpUprobeWorker{attachCandidates: make(chan httpUprobeAttachCandidate, 1)}
		worker.queueAttachCandidate(candidate)
		select {
		case got := <-worker.attachCandidates:
			if got != candidate {
				t.Fatalf("queued attach candidate = %+v, want %+v", got, candidate)
			}
		default:
			t.Fatal("expected an attach candidate, queue was empty")
		}
	})

	t.Run("full queue drops the attach candidate without blocking", func(t *testing.T) {
		t.Parallel()
		worker := &httpUprobeWorker{attachCandidates: make(chan httpUprobeAttachCandidate, 1)}
		worker.queueAttachCandidate(candidate)
		worker.queueAttachCandidate(httpUprobeAttachCandidate{tgid: 9876})
		if len(worker.attachCandidates) != 1 {
			t.Fatalf("queue len = %d, want 1", len(worker.attachCandidates))
		}
		if worker.attachCandidateQueueDropped != 1 {
			t.Fatalf("attachCandidateQueueDropped = %d, want 1", worker.attachCandidateQueueDropped)
		}
	})
}

func TestParseExecMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		line               string
		wantStart, wantEnd uint64
	}{
		{name: "executable file-backed mapping", line: "55a1b2c00000-55a1b2c21000 r-xp 00000000 fd:01 1443212 /usr/lib/libssl.so.3", wantStart: 0x55a1b2c00000, wantEnd: 0x55a1b2c21000},
		{name: "zero-padded address becomes numeric map_files range", line: "00400000-066a1000 r-xp 00000000 08:01 1443212 /usr/bin/node", wantStart: 0x400000, wantEnd: 0x66a1000},
		{name: "deleted file still has a usable mapping", line: "400000-401000 r-xp 00000000 08:01 12 /tmp/client (deleted)", wantStart: 0x400000, wantEnd: 0x401000},
		{name: "visible identity is not used to select a range", line: "400000-401000 r-xp 00000000 visible visible /usr/bin/node", wantStart: 0x400000, wantEnd: 0x401000},
		{name: "non-executable mapping is skipped", line: "400000-401000 r--p 00000000 fd:01 12 /usr/lib/libssl.so.3"},
		{name: "anonymous inode is skipped", line: "400000-401000 r-xp 00000000 00:00 0 /anon"},
		{name: "special mapping is skipped", line: "400000-401000 r-xp 00000000 00:00 1 [vdso]"},
		{name: "no pathname field is skipped", line: "400000-401000 r-xp 00000000 00:00 12345"},
		{name: "empty line is skipped"},
		{name: "short permissions are skipped", line: "400000-401000 r- 00000000 08:01 12 /bin/client"},
		{name: "missing range separator is skipped", line: "400000 r-xp 00000000 08:01 12 /bin/client"},
		{name: "invalid range start is skipped", line: "invalid-401000 r-xp 00000000 08:01 12 /bin/client"},
		{name: "invalid range end is skipped", line: "400000-invalid r-xp 00000000 08:01 12 /bin/client"},
		{name: "empty range is skipped", line: "400000-400000 r-xp 00000000 08:01 12 /bin/client"},
		{name: "reversed range is skipped", line: "401000-400000 r-xp 00000000 08:01 12 /bin/client"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			start, end, ok := parseExecMapping(tt.line)
			if start != tt.wantStart || end != tt.wantEnd || ok != (tt.wantEnd != 0) {
				t.Fatalf("range = %x-%x, ok=%v; want %x-%x", start, end, ok, tt.wantStart, tt.wantEnd)
			}
		})
	}
}

func TestMappedFilePath(t *testing.T) {
	t.Parallel()
	if got, want := mappedFilePath(123, 0x00400000, 0x066a1000), "/proc/123/map_files/400000-66a1000"; got != want {
		t.Fatalf("mappedFilePath = %q, want %q", got, want)
	}
}

func TestProcessIsGone(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		&os.PathError{Op: "open", Path: "/proc/1/maps", Err: os.ErrNotExist},
		&os.PathError{Op: "open", Path: "/proc/1/maps", Err: unix.ESRCH},
	} {
		if !processIsGone(err) {
			t.Fatalf("processIsGone(%v) = false, want true", err)
		}
	}
	if processIsGone(&os.PathError{Op: "open", Path: filepath.Join("proc", "1", "maps"), Err: os.ErrPermission}) {
		t.Fatal("permission error reported as a gone process")
	}
}
