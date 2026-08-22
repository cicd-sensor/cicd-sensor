//go:build linux

package kernelio

import (
	"bufio"
	"os"
	"testing"
	"time"
)

// reclaimHarness drives reconcile() against a worker whose registry is seeded
// with link-less entries (closeLinks on an empty slice is a no-op), so the
// tests exercise the reclaim decision logic — miss counting, the
// ScanStartedAt contract, fail-keep — without real uprobe links. Identities
// are "present" only if a snapshot PID's maps list them; here no PIDs are
// scanned (PIDs is empty), so every attached target is absent unless a test
// injects presence via the seen-during-scan path (lastSeenAt).
type reclaimHarness struct {
	d   *httpUprobeDiscovery
	now time.Time
}

func newReclaimHarness(t *testing.T) *reclaimHarness {
	t.Helper()
	h := &reclaimHarness{now: time.Unix(1_000_000, 0).UTC()}
	h.d = newHTTPUprobeDiscovery(nil, nil)
	h.d.now = func() time.Time { return h.now }
	return h
}

func (h *reclaimHarness) attached(id fileIdentity) *registryEntry {
	e := &registryEntry{lastSeenAt: h.now}
	h.d.targets[id] = e
	return e
}

// complete/incomplete snapshots with no PIDs: every target is absent.
func (h *reclaimHarness) sweep(complete bool) {
	h.now = h.now.Add(time.Minute)
	h.d.reconcile(MappedProcessSnapshot{ScanStartedAt: h.now, Complete: complete})
}

func TestHTTPUprobeReclaim(t *testing.T) {
	t.Parallel()
	id := fileIdentity{dev: 1, ino: 42}

	t.Run("two complete missing observations close the target", func(t *testing.T) {
		t.Parallel()
		h := newReclaimHarness(t)
		e := h.attached(id)
		h.sweep(true)
		if e.missedScans != 1 {
			t.Fatalf("after 1st miss: missedScans = %d, want 1", e.missedScans)
		}
		if _, still := h.d.targets[id]; !still {
			t.Fatal("closed after a single miss; must survive the first")
		}
		h.sweep(true)
		if _, still := h.d.targets[id]; still {
			t.Fatal("still attached after two complete misses; must be closed")
		}
	})

	t.Run("incomplete scan neither advances nor resets the miss count", func(t *testing.T) {
		t.Parallel()
		h := newReclaimHarness(t)
		e := h.attached(id)
		h.sweep(true) // miss 1
		h.sweep(false)
		if e.missedScans != 1 {
			t.Fatalf("incomplete scan changed missedScans to %d, want 1 (untouched)", e.missedScans)
		}
		if _, still := h.d.targets[id]; !still {
			t.Fatal("incomplete scan must never close")
		}
		// complete-missing, incomplete, complete-missing  => closes
		h.sweep(true)
		if _, still := h.d.targets[id]; still {
			t.Fatal("second complete miss across an incomplete scan must close")
		}
	})

	t.Run("a processed observation at or after ScanStartedAt blocks close", func(t *testing.T) {
		t.Parallel()
		h := newReclaimHarness(t)
		e := h.attached(id)
		h.sweep(true) // miss 1
		// The worker processes a discovery observation of this target AFTER the
		// next scan starts but before the snapshot is handled: lastSeenAt moves
		// to >= ScanStartedAt, so that snapshot must not count a miss.
		scanStart := h.now.Add(time.Minute)
		e.lastSeenAt = scanStart.Add(time.Second)
		h.now = scanStart
		h.d.reconcile(MappedProcessSnapshot{ScanStartedAt: scanStart, Complete: true})
		if e.missedScans != 1 {
			t.Fatalf("observed-during-scan target had missedScans advanced to %d, want 1", e.missedScans)
		}
		if _, still := h.d.targets[id]; !still {
			t.Fatal("observed-during-scan target was closed")
		}
	})

	t.Run("nothing tracked: empty complete snapshot reclaims unused targets", func(t *testing.T) {
		t.Parallel()
		h := newReclaimHarness(t)
		h.attached(id)
		h.sweep(true)
		h.sweep(true)
		if len(h.d.targets) != 0 {
			t.Fatalf("targets = %d, want 0 after two empty complete snapshots", len(h.d.targets))
		}
	})

	t.Run("enqueueSnapshot never blocks and keeps only the latest", func(t *testing.T) {
		t.Parallel()
		d := newHTTPUprobeDiscovery(nil, nil)
		d.enqueueSnapshot(MappedProcessSnapshot{ScannedCgroups: 1})
		d.enqueueSnapshot(MappedProcessSnapshot{ScannedCgroups: 2}) // must not block on a full buffer
		select {
		case got := <-d.snapshots:
			if got.ScannedCgroups != 2 {
				t.Fatalf("queued snapshot = %d, want the latest (2)", got.ScannedCgroups)
			}
		default:
			t.Fatal("no snapshot queued")
		}
	})
}

func TestScanProcessIntoCompleteness(t *testing.T) {
	t.Parallel()

	t.Run("gone pid (ENOENT) is the benign race: complete", func(t *testing.T) {
		t.Parallel()
		d := newHTTPUprobeDiscovery(nil, nil)
		// PID 2^31-1 does not exist on any sane box.
		if !d.scanProcessInto(2147483647, nil) {
			t.Fatal("ENOENT on /proc/<pid>/maps must be reported complete (benign race)")
		}
	})

	t.Run("target cap reached: presence still probed, scan still complete, no new attach", func(t *testing.T) {
		t.Parallel()
		requireMapFilesAccess(t) // presence is derived via /proc/<pid>/map_files (needs CAP_SYS_ADMIN/CHECKPOINT_RESTORE)
		d := newHTTPUprobeDiscovery(nil, nil)
		for i := 0; i < maxUprobeTargets; i++ { // fill the registry to the cap
			d.targets[fileIdentity{dev: 1, ino: uint64(i) + 1}] = &registryEntry{}
		}
		before := len(d.targets)
		present := map[fileIdentity]struct{}{}
		// The cap must only refuse NEW attaches. The probe still walks every
		// mapping and records presence, and stays complete — otherwise a capped
		// registry could never reclaim a stale link and would never clear.
		if !d.scanProcessInto(int32(os.Getpid()), present) {
			t.Fatal("cap-reached scan reported incomplete; reclaim would be frozen at the cap forever")
		}
		if len(present) == 0 {
			t.Fatal("cap-reached scan recorded no presence; liveness of attached targets would be invisible")
		}
		if len(d.targets) != before {
			t.Fatalf("targets grew at cap: %d -> %d (refuse-not-evict violated)", before, len(d.targets))
		}
	})
}

// requireMapFilesAccess skips when this process cannot open its own
// /proc/self/map_files entries (EPERM without CAP_SYS_ADMIN or
// CAP_CHECKPOINT_RESTORE — e.g. an unprivileged container). The presence probe
// depends on that access, so the test is only meaningful where it works.
func requireMapFilesAccess(t *testing.T) {
	t.Helper()
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		t.Skipf("cannot read /proc/self/maps: %v", err)
	}
	defer f.Close()
	// Try every executable file-backed mapping: on some kernels the main
	// executable's low mapping is not an exact VMA (ENOENT via map_files) even
	// for root, while shared-library mappings open fine. Skip only if none do.
	scanner := bufio.NewScanner(f)
	var lastErr error
	for scanner.Scan() {
		rng, _, ok := parseExecMapping(scanner.Text())
		if !ok {
			continue
		}
		mf, err := os.Open("/proc/self/map_files/" + rng)
		if err != nil {
			lastErr = err
			continue
		}
		mf.Close()
		return
	}
	t.Skipf("no map_files entry openable here (last: %v); needs CAP_SYS_ADMIN/CAP_CHECKPOINT_RESTORE", lastErr)
}
