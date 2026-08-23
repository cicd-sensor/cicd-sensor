//go:build linux

package kernelio

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// reclaimHarness drives reconcile() against a worker whose registry is seeded
// with link-less entries (closeLinks on an empty slice is a no-op), so the
// tests exercise miss counting and fail-keep without real uprobe links. The
// reconciliations contain no cgroup paths, so every attached target is absent.
type reclaimHarness struct {
	d *httpUprobeDiscovery
}

func newReclaimHarness(t *testing.T) *reclaimHarness {
	t.Helper()
	return &reclaimHarness{d: newHTTPUprobeDiscovery(nil, nil)}
}

func (h *reclaimHarness) attached(id fileClassificationKey) *attachedUprobeTarget {
	e := &attachedUprobeTarget{}
	h.d.attachedTargets[id.mappedFile] = e
	return e
}

// An empty path set makes every target absent.
func (h *reclaimHarness) sweep() {
	h.d.reconcile(nil)
}

func TestHTTPUprobeReclaim(t *testing.T) {
	t.Parallel()
	id := fileClassificationKey{mappedFile: "1:42"}

	t.Run("two complete missing observations close the target", func(t *testing.T) {
		t.Parallel()
		h := newReclaimHarness(t)
		e := h.attached(id)
		h.sweep()
		if e.missingScanCount != 1 {
			t.Fatalf("after 1st miss: missingScanCount = %d, want 1", e.missingScanCount)
		}
		if _, still := h.d.attachedTargets[id.mappedFile]; !still {
			t.Fatal("closed after a single miss; must survive the first")
		}
		h.sweep()
		if _, still := h.d.attachedTargets[id.mappedFile]; still {
			t.Fatal("still attached after two complete misses; must be closed")
		}
	})

	t.Run("incomplete scan without observations neither advances nor closes", func(t *testing.T) {
		t.Parallel()
		h := newReclaimHarness(t)
		e := h.attached(id)
		h.sweep() // miss 1
		notDirectory := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(notDirectory, nil, 0o644); err != nil {
			t.Fatalf("write non-directory cgroup path: %v", err)
		}
		h.d.reconcile([]string{notDirectory})
		if e.missingScanCount != 1 {
			t.Fatalf("empty incomplete scan changed missingScanCount to %d, want 1", e.missingScanCount)
		}
		if _, still := h.d.attachedTargets[id.mappedFile]; !still {
			t.Fatal("incomplete scan must never close")
		}
		// complete-missing, incomplete, complete-missing => closes
		h.sweep()
		if _, still := h.d.attachedTargets[id.mappedFile]; still {
			t.Fatal("second complete miss across an incomplete scan must close")
		}
	})
	t.Run("enqueueReconciliation never blocks and keeps only the latest", func(t *testing.T) {
		t.Parallel()
		d := newHTTPUprobeDiscovery(nil, nil)
		staleResult := make(chan int, 1)
		d.enqueueReconciliation([]string{"one"}, staleResult)
		d.enqueueReconciliation([]string{"two"}, nil) // must not block on a full buffer
		if result := <-staleResult; result != -1 {
			t.Fatalf("replaced reconciliation result = %d, want -1", result)
		}
		select {
		case got := <-d.reconciliations:
			if !slices.Equal(got.cgroupPaths, []string{"two"}) {
				t.Fatalf("queued cgroup paths = %v, want [two]", got.cgroupPaths)
			}
		default:
			t.Fatal("no reconciliation queued")
		}
	})

	t.Run("reconcile handoff copies the cgroup path slice", func(t *testing.T) {
		t.Parallel()
		d := newHTTPUprobeDiscovery(nil, nil)
		kernelIO := &LinuxKernelIO{httpUprobeDiscovery: d}
		paths := []string{"one"}
		kernelIO.QueueHTTPUprobeReconciliation(paths)
		paths[0] = "two"
		got := <-d.reconciliations
		if !slices.Equal(got.cgroupPaths, []string{"one"}) {
			t.Fatalf("queued paths = %v, want immutable copy [one]", got.cgroupPaths)
		}
	})
}

func TestCollectCgroupPIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		contents string
		missing  bool
		complete bool
		want     []int32
	}{
		{name: "valid members are deduplicated", contents: "123\n456\n123\n", complete: true, want: []int32{123, 456}},
		{name: "malformed member makes the scan incomplete", contents: "123\ninvalid\n0\n-1\n", complete: false, want: []int32{123}},
		{name: "vanished cgroup is a complete teardown race", missing: true, complete: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "tracked")
			if !test.missing {
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatalf("mkdir tracked cgroup: %v", err)
				}
				if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(test.contents), 0o644); err != nil {
					t.Fatalf("write cgroup.procs: %v", err)
				}
			}

			d := newHTTPUprobeDiscovery(nil, nil)
			got := make(map[int32]struct{})
			if complete := d.collectCgroupPIDs(path, got); complete != test.complete {
				t.Fatalf("complete = %v, want %v", complete, test.complete)
			}
			gotPIDs := slices.Sorted(maps.Keys(got))
			if !slices.Equal(gotPIDs, test.want) {
				t.Fatalf("PIDs = %v, want %v", gotPIDs, test.want)
			}
		})
	}
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

	t.Run("observed targets reset their missing count", func(t *testing.T) {
		t.Parallel()
		d := newHTTPUprobeDiscovery(nil, nil)
		data, err := os.ReadFile("/proc/self/maps")
		if err != nil {
			t.Fatalf("read own maps: %v", err)
		}
		for line := range strings.Lines(string(data)) {
			_, mapped, ok := parseExecMapping(line)
			if ok {
				d.attachedTargets[mapped] = &attachedUprobeTarget{missingScanCount: 1}
			}
		}
		if len(d.attachedTargets) == 0 {
			t.Fatal("own maps contained no executable file mapping")
		}
		if !d.scanProcessInto(int32(os.Getpid()), nil) {
			t.Fatal("scan of own maps reported incomplete")
		}
		for mapped, target := range d.attachedTargets {
			if target.missingScanCount != 0 {
				t.Fatalf("target %v missingScanCount = %d, want 0", mapped, target.missingScanCount)
			}
		}
	})

	t.Run("target cap reached: presence still probed, scan still complete, no new attach", func(t *testing.T) {
		t.Parallel()
		d := newHTTPUprobeDiscovery(nil, nil)
		for i := 0; i < maxAttachedUprobeTargets; i++ { // fill the registry to the cap
			mapped := mappedFileID(strconv.Itoa(i + 1))
			d.attachedTargets[mapped] = &attachedUprobeTarget{}
		}
		before := len(d.attachedTargets)
		present := map[mappedFileID]struct{}{}
		// The cap must only refuse NEW attaches. The probe still walks every
		// mapping and records presence, and stays complete — otherwise a capped
		// registry could never reclaim a stale link and would never clear.
		if !d.scanProcessInto(int32(os.Getpid()), present) {
			t.Fatal("cap-reached scan reported incomplete; reclaim would be frozen at the cap forever")
		}
		if len(present) == 0 {
			t.Fatal("cap-reached scan recorded no presence; liveness of attached targets would be invisible")
		}
		if len(d.attachedTargets) != before {
			t.Fatalf("targets grew at cap: %d -> %d (refuse-not-evict violated)", before, len(d.attachedTargets))
		}
	})
}
