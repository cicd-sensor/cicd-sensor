package kernelio

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestConfigureBPFProgramSpecSetsStagingCap(t *testing.T) {
	t.Parallel()

	spec := fakeProgramSpec()

	if err := configureBPFProgramSpec(spec); err != nil {
		t.Fatalf("configureBPFProgramSpec returned error: %v", err)
	}

	if got := spec.Maps[StagingMapName].MaxEntries; got != StagingMaxEntries {
		t.Fatalf("staging map max entries: got %d, want %d", got, StagingMaxEntries)
	}
}

func TestConfigureBPFProgramSpecErrorsOnMissingStagingMap(t *testing.T) {
	t.Parallel()

	spec := fakeProgramSpec()
	delete(spec.Maps, StagingMapName)

	if err := configureBPFProgramSpec(spec); err == nil {
		t.Fatalf("expected missing staging map error")
	}
}

func fakeProgramSpec() *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			StagingMapName: {},
		},
	}
}
