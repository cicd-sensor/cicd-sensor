//go:build linux

package kernelio

import (
	"testing"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cilium/ebpf"
)

func TestHTTPUprobeDiscoveryCacheUsesBoundedLRU(t *testing.T) {
	t.Parallel()
	const mapName = "http_uprobe_discovery_cache"

	spec, err := bpfprog.LoadBPFProgram()
	if err != nil {
		t.Fatalf("load BPF program spec: %v", err)
	}
	cache := spec.Maps[mapName]
	if cache == nil {
		t.Fatalf("BPF map %q not found", mapName)
	}
	if cache.Type != ebpf.LRUHash {
		t.Fatalf("discovery cache type = %s, want LRUHash", cache.Type)
	}
	if cache.MaxEntries != 65536 {
		t.Fatalf("discovery cache max entries = %d, want 65536", cache.MaxEntries)
	}
}

func TestHTTPUprobeStopLeasesUseBoundedNonEvictingMap(t *testing.T) {
	t.Parallel()
	spec, err := bpfprog.LoadBPFProgram()
	if err != nil {
		t.Fatalf("load BPF program spec: %v", err)
	}
	leases := spec.Maps[httpUprobeStopMapName]
	if leases == nil {
		t.Fatalf("BPF map %q not found", httpUprobeStopMapName)
	}
	if leases.Type != ebpf.Hash {
		t.Fatalf("stop lease map type = %s, want Hash", leases.Type)
	}
	if leases.MaxEntries != 4096 {
		t.Fatalf("stop lease map max entries = %d, want 4096", leases.MaxEntries)
	}
	if leases.ValueSize != 8 {
		t.Fatalf("stop lease value size = %d, want one uint64 timestamp", leases.ValueSize)
	}
}

func TestHTTPUprobeAttachCandidatesUseDedicatedRingbuf(t *testing.T) {
	t.Parallel()
	const mapName = "http_uprobe_attach_candidates"

	spec, err := bpfprog.LoadBPFProgram()
	if err != nil {
		t.Fatalf("load BPF program spec: %v", err)
	}
	candidates := spec.Maps[mapName]
	if candidates == nil {
		t.Fatalf("BPF map %q not found", mapName)
	}
	if candidates.Type != ebpf.RingBuf {
		t.Fatalf("attach candidate map type = %s, want RingBuf", candidates.Type)
	}
	if candidates.MaxEntries != 1<<20 {
		t.Fatalf("attach candidate ringbuf max entries = %d, want %d", candidates.MaxEntries, 1<<20)
	}

	discovery := spec.Programs[bpfprog.BPFProgramProgHandleUprobeMmap]
	if discovery == nil {
		t.Fatalf("BPF program %q not found", bpfprog.BPFProgramProgHandleUprobeMmap)
	}
	var usesDedicatedRingbuf, usesEventRingbuf bool
	for _, instruction := range discovery.Instructions {
		switch instruction.Reference() {
		case mapName:
			usesDedicatedRingbuf = true
		case eventsMapName:
			usesEventRingbuf = true
		}
	}
	if !usesDedicatedRingbuf {
		t.Fatalf("BPF program %q does not reference %q", bpfprog.BPFProgramProgHandleUprobeMmap, mapName)
	}
	if usesEventRingbuf {
		t.Fatalf("BPF program %q references security-event ringbuf %q", bpfprog.BPFProgramProgHandleUprobeMmap, eventsMapName)
	}
}
