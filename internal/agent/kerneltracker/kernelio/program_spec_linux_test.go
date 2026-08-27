//go:build linux

package kernelio

import (
	"testing"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cilium/ebpf"
)

func TestHTTPUprobeDiscoveryCacheUsesBoundedLRU(t *testing.T) {
	t.Parallel()

	spec, err := bpfprog.LoadBPFProgram()
	if err != nil {
		t.Fatalf("load BPF program spec: %v", err)
	}
	cache := spec.Maps[httpUprobeDiscoveryCacheMapName]
	if cache == nil {
		t.Fatalf("BPF map %q not found", httpUprobeDiscoveryCacheMapName)
	}
	if cache.Type != ebpf.LRUHash {
		t.Fatalf("discovery cache type = %s, want LRUHash", cache.Type)
	}
	if cache.MaxEntries != 65536 {
		t.Fatalf("discovery cache max entries = %d, want 65536", cache.MaxEntries)
	}
}
