package kernelio

import (
	"fmt"
	"math"
	"math/bits"
	"runtime"

	"github.com/cilium/ebpf"
)

const (
	eventsMapName              = "events"
	httpUprobeNonTargetMapName = "non_target_files"
	httpUprobeSeenMapName      = "http_uprobe_seen_mappings"
	disabledHTTPUprobeMapSize  = 1
	// Keep at least 8 MiB for small CI/CD runner nodes.
	minEventsRingbufMaxEntries = 8 << 20
	// Add 4 MiB per CPU so larger runner nodes get more ingress capacity.
	eventsRingbufMaxBytesPerCPU = 4 << 20
)

// configureBPFProgramSpec applies userspace-owned map settings before load.
func configureBPFProgramSpec(spec *ebpf.CollectionSpec, enableHTTPUprobes bool) error {
	eventsMap := spec.Maps[eventsMapName]
	if eventsMap == nil {
		return fmt.Errorf("bpf map %q not found", eventsMapName)
	}
	eventsMaxEntries, err := eventsRingbufMaxEntries(runtime.NumCPU())
	if err != nil {
		return err
	}
	eventsMap.MaxEntries = eventsMaxEntries

	stagingMap := spec.Maps[StagingMapName]
	if stagingMap == nil {
		return fmt.Errorf("bpf map %q not found", StagingMapName)
	}
	stagingMap.MaxEntries = StagingMaxEntries

	for _, name := range []string{httpUprobeNonTargetMapName, httpUprobeSeenMapName} {
		uprobeMap := spec.Maps[name]
		if uprobeMap == nil {
			return fmt.Errorf("bpf map %q not found", name)
		}
		if !enableHTTPUprobes {
			// Programs still load for verifier compatibility, but disabled HTTP
			// uprobes must not reserve their production cache capacity.
			uprobeMap.MaxEntries = disabledHTTPUprobeMapSize
		}
	}
	return nil
}

func eventsRingbufMaxEntries(cpuCount int) (uint32, error) {
	if cpuCount <= 0 {
		return 0, fmt.Errorf("cpu count must be positive, got %d", cpuCount)
	}

	size := uint64(cpuCount) * eventsRingbufMaxBytesPerCPU
	size = max(size, minEventsRingbufMaxEntries)

	// BPF_MAP_TYPE_RINGBUF requires max_entries to be a power of two.
	rounded := roundUpToPowerOfTwo(size)
	if rounded > math.MaxUint32 {
		return 0, fmt.Errorf("events ringbuf max entries %d exceed uint32", rounded)
	}
	return uint32(rounded), nil
}

func roundUpToPowerOfTwo(value uint64) uint64 {
	if value <= 1 {
		return 1
	}
	return 1 << bits.Len64(value-1)
}
