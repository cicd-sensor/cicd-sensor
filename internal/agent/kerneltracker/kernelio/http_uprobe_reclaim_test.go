//go:build linux

package kernelio

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// reclaimHarness drives reconcile() against a worker whose registry is seeded
// with link-less entries (closeLinks on an empty slice is a no-op), so the
// tests exercise miss counting and fail-keep without real uprobe links. The
// Reconcile requests contain no active cgroup IDs, so every target is absent.
type reclaimHarness struct {
	d *httpUprobeDiscovery
}

func newReclaimHarness(t *testing.T) *reclaimHarness {
	t.Helper()
	return &reclaimHarness{d: newHTTPUprobeDiscovery(nil, nil, t.TempDir(), nil)}
}

func (h *reclaimHarness) attached(id mappedFileIdentity) *attachedUprobeTarget {
	e := &attachedUprobeTarget{}
	h.d.attachedTargets[id] = e
	return e
}

// An empty active-ID snapshot makes every target absent.
func (h *reclaimHarness) sweep() {
	h.d.reconcileTargets(nil)
}

func TestHTTPUprobeReclaim(t *testing.T) {
	t.Parallel()
	id := mappedFileIdentity{deviceMajor: 1, inode: 42}

	t.Run("two complete missing observations close the target", func(t *testing.T) {
		t.Parallel()
		h := newReclaimHarness(t)
		e := h.attached(id)
		h.sweep()
		if e.missingScanCount != 1 {
			t.Fatalf("after 1st miss: missingScanCount = %d, want 1", e.missingScanCount)
		}
		if _, still := h.d.attachedTargets[id]; !still {
			t.Fatal("closed after a single miss; must survive the first")
		}
		h.sweep()
		if _, still := h.d.attachedTargets[id]; still {
			t.Fatal("still attached after two complete misses; must be closed")
		}
	})

	t.Run("incomplete scan without observations neither advances nor closes", func(t *testing.T) {
		t.Parallel()
		h := newReclaimHarness(t)
		e := h.attached(id)
		h.sweep() // miss 1
		cgroupPath := filepath.Join(h.d.cgroupRootPath, "unreadable")
		if err := os.MkdirAll(filepath.Join(cgroupPath, "cgroup.procs"), 0o755); err != nil {
			t.Fatalf("create invalid cgroup.procs: %v", err)
		}
		h.d.reconcileTargets([]uint64{testPathInode(t, cgroupPath)})
		if e.missingScanCount != 1 {
			t.Fatalf("empty incomplete scan changed missingScanCount to %d, want 1", e.missingScanCount)
		}
		if _, still := h.d.attachedTargets[id]; !still {
			t.Fatal("incomplete scan must never close")
		}
		// complete-missing, incomplete, complete-missing => closes
		h.sweep()
		if _, still := h.d.attachedTargets[id]; still {
			t.Fatal("second complete miss across an incomplete scan must close")
		}
	})
	t.Run("queueTargetReconciliation never blocks and keeps one pending sweep", func(t *testing.T) {
		t.Parallel()
		d := newHTTPUprobeDiscovery(nil, nil, t.TempDir(), nil)
		d.queueTargetReconciliation([]uint64{1})
		d.queueTargetReconciliation([]uint64{2}) // must not block on a full buffer
		select {
		case got := <-d.reconcileRequests:
			if !slices.Equal(got, []uint64{1}) {
				t.Fatalf("queued cgroup IDs = %v, want first pending snapshot [1]", got)
			}
		default:
			t.Fatal("no reconciliation queued")
		}
	})
}

func TestResolveActiveCgroupPaths(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	tracked := filepath.Join(root, "tracked")
	untracked := filepath.Join(root, "untracked")
	if err := os.MkdirAll(tracked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(untracked, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("resolves only active IDs", func(t *testing.T) {
		paths, complete := resolveActiveCgroupPaths(root, []uint64{testPathInode(t, tracked)})
		if !complete {
			t.Fatal("complete = false, want true")
		}
		if !slices.Equal(paths, []string{tracked}) {
			t.Fatalf("paths = %v, want [%s]", paths, tracked)
		}
	})

	t.Run("empty IDs avoid filesystem dependency", func(t *testing.T) {
		paths, complete := resolveActiveCgroupPaths("", nil)
		if !complete || len(paths) != 0 {
			t.Fatalf("paths = %v complete = %v, want empty true", paths, complete)
		}
	})

	t.Run("missing root is incomplete", func(t *testing.T) {
		paths, complete := resolveActiveCgroupPaths(filepath.Join(root, "missing"), []uint64{1})
		if complete || len(paths) != 0 {
			t.Fatalf("paths = %v complete = %v, want empty false", paths, complete)
		}
	})
}

func testPathInode(t *testing.T, path string) uint64 {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	return stat.Ino
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

			d := newHTTPUprobeDiscovery(nil, nil, t.TempDir(), nil)
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

func TestScanProcessMappingsCompleteness(t *testing.T) {
	t.Parallel()

	t.Run("gone pid (ENOENT) is the benign race: complete", func(t *testing.T) {
		t.Parallel()
		d := newHTTPUprobeDiscovery(nil, nil, t.TempDir(), nil)
		// PID 2^31-1 does not exist on any sane box.
		mappings, complete := d.scanProcessMappings(2147483647)
		if !complete {
			t.Fatal("ENOENT on /proc/<pid>/maps must be reported complete (benign race)")
		}
		if len(mappings) != 0 {
			t.Fatalf("mappings = %d, want 0", len(mappings))
		}
	})

	t.Run("own executable file mappings are returned", func(t *testing.T) {
		t.Parallel()
		d := newHTTPUprobeDiscovery(nil, nil, t.TempDir(), nil)
		mappings, complete := d.scanProcessMappings(int32(os.Getpid()))
		if !complete {
			t.Fatal("scan of own maps reported incomplete")
		}
		if len(mappings) == 0 {
			t.Fatal("own maps contained no executable file mapping")
		}
	})

	t.Run("target cap does not affect mapping scan", func(t *testing.T) {
		t.Parallel()
		d := newHTTPUprobeDiscovery(nil, nil, t.TempDir(), nil)
		for i := 0; i < maxAttachedUprobeTargets; i++ { // fill the registry to the cap
			mapped := mappedFileIdentity{inode: uint64(i + 1)}
			d.attachedTargets[mapped] = &attachedUprobeTarget{}
		}
		mappings, complete := d.scanProcessMappings(int32(os.Getpid()))
		if !complete {
			t.Fatal("cap-reached scan reported incomplete; reclaim would be frozen at the cap forever")
		}
		if len(mappings) == 0 {
			t.Fatal("cap-reached scan recorded no presence; liveness of attached targets would be invisible")
		}
	})
}
