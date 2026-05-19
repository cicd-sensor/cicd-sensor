package kernelio

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// configureBPFProgramSpec applies userspace-owned map settings before load.
func configureBPFProgramSpec(spec *ebpf.CollectionSpec) error {
	stagingMap := spec.Maps[StagingMapName]
	if stagingMap == nil {
		return fmt.Errorf("bpf map %q not found", StagingMapName)
	}
	stagingMap.MaxEntries = StagingMaxEntries
	return nil
}
