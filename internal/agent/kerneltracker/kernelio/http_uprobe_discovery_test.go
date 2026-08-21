//go:build linux

package kernelio

import "testing"

func TestHTTPUprobeDiscoveryEnqueuePID(t *testing.T) {
	t.Parallel()

	t.Run("available queue records the process pid", func(t *testing.T) {
		t.Parallel()

		d := &httpUprobeDiscovery{hints: make(chan int32, 1)}
		d.enqueuePID(4321)
		select {
		case got := <-d.hints:
			if got != 4321 {
				t.Fatalf("hinted pid = %d, want 4321", got)
			}
		default:
			t.Fatal("expected a hint, queue was empty")
		}
	})

	t.Run("full queue drops the hint without blocking", func(t *testing.T) {
		t.Parallel()

		d := &httpUprobeDiscovery{hints: make(chan int32, 1)}
		d.enqueuePID(1) // fills the queue
		d.enqueuePID(2) // must not block
		if len(d.hints) != 1 {
			t.Fatalf("queue len = %d, want 1 (second hint must be dropped)", len(d.hints))
		}
		if d.queueDropped != 1 {
			t.Fatalf("queueDropped = %d, want 1", d.queueDropped)
		}
	})
}

func TestParseExecMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		line       string
		wantOK     bool
		wantRange  string
		wantDevIno string
	}{
		{
			name:       "executable file-backed mapping",
			line:       "55a1b2c00000-55a1b2c21000 r-xp 00000000 fd:01 1443212 /usr/lib/x86_64-linux-gnu/libssl.so.3",
			wantOK:     true,
			wantRange:  "55a1b2c00000-55a1b2c21000",
			wantDevIno: "fd:01:1443212",
		},
		{
			name:   "non-executable mapping is skipped",
			line:   "55a1b2c21000-55a1b2c25000 r--p 00021000 fd:01 1443212 /usr/lib/x86_64-linux-gnu/libssl.so.3",
			wantOK: false,
		},
		{
			name:   "anonymous mapping (inode 0) is skipped",
			line:   "7f0000000000-7f0000001000 r-xp 00000000 00:00 0 ",
			wantOK: false,
		},
		{
			name:   "special mapping [vdso] is skipped",
			line:   "7ffff7fce000-7ffff7fd0000 r-xp 00000000 00:00 0 [vdso]",
			wantOK: false,
		},
		{
			name:   "no pathname field is skipped",
			line:   "7ffff7fce000-7ffff7fd0000 r-xp 00000000 00:00 12345",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rng, devIno, ok := parseExecMapping(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if rng != tt.wantRange {
				t.Fatalf("range = %q, want %q", rng, tt.wantRange)
			}
			if devIno != tt.wantDevIno {
				t.Fatalf("devIno = %q, want %q", devIno, tt.wantDevIno)
			}
		})
	}
}

func TestFIFOSet(t *testing.T) {
	t.Parallel()

	id := func(n uint64) fileIdentity { return fileIdentity{dev: 1, ino: n} }

	t.Run("add then has", func(t *testing.T) {
		t.Parallel()
		s := newFIFOSet(4)
		if s.has(id(1)) {
			t.Fatal("empty set reports membership")
		}
		s.add(id(1))
		if !s.has(id(1)) {
			t.Fatal("added identity not found")
		}
	})

	t.Run("duplicate add does not grow", func(t *testing.T) {
		t.Parallel()
		s := newFIFOSet(2)
		s.add(id(1))
		s.add(id(1))
		s.add(id(2))
		// Both distinct identities fit; a third distinct one would evict the
		// oldest, so id(1) must still be present here.
		if !s.has(id(1)) || !s.has(id(2)) {
			t.Fatalf("duplicate add mis-counted: has(1)=%v has(2)=%v", s.has(id(1)), s.has(id(2)))
		}
	})

	t.Run("eviction is FIFO oldest-first", func(t *testing.T) {
		t.Parallel()
		s := newFIFOSet(2)
		s.add(id(1)) // oldest
		s.add(id(2))
		s.add(id(3)) // evicts id(1)
		if s.has(id(1)) {
			t.Fatal("oldest identity should have been evicted")
		}
		if !s.has(id(2)) || !s.has(id(3)) {
			t.Fatalf("recent identities missing: has(2)=%v has(3)=%v", s.has(id(2)), s.has(id(3)))
		}
	})
}
