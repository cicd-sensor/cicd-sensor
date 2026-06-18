package kernelio

import (
	"runtime"
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

func TestConfigureBPFProgramSpecSetsEventsRingbufCap(t *testing.T) {
	t.Parallel()

	spec := fakeProgramSpec()

	if err := configureBPFProgramSpec(spec); err != nil {
		t.Fatalf("configureBPFProgramSpec returned error: %v", err)
	}

	want, err := eventsRingbufMaxEntries(runtime.NumCPU())
	if err != nil {
		t.Fatalf("eventsRingbufMaxEntries returned error: %v", err)
	}
	if got := spec.Maps[eventsMapName].MaxEntries; got != want {
		t.Fatalf("events ringbuf max entries: got %d, want %d", got, want)
	}
}

func TestConfigureBPFProgramSpecErrorsOnMissingEventsMap(t *testing.T) {
	t.Parallel()

	spec := fakeProgramSpec()
	delete(spec.Maps, eventsMapName)

	if err := configureBPFProgramSpec(spec); err == nil {
		t.Fatalf("expected missing events map error")
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

func TestEventsRingbufMaxEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cpus     int
		expected uint32
		wantErr  bool
	}{
		{name: "minimum for one CPU", cpus: 1, expected: 8 << 20},
		{name: "minimum for two CPUs", cpus: 2, expected: 8 << 20},
		{name: "linear for four CPUs", cpus: 4, expected: 16 << 20},
		{name: "rounds six CPUs up to next power of two", cpus: 6, expected: 32 << 20},
		{name: "linear for eight CPUs", cpus: 8, expected: 32 << 20},
		{name: "rejects zero CPUs", cpus: 0, wantErr: true},
		{name: "rejects rounded size beyond uint32", cpus: 1024, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := eventsRingbufMaxEntries(tc.cpus)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("eventsRingbufMaxEntries returned error: %v", err)
			}
			if got != tc.expected {
				t.Fatalf("eventsRingbufMaxEntries: got %d, want %d", got, tc.expected)
			}
		})
	}
}

func fakeProgramSpec() *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			eventsMapName:  {},
			StagingMapName: {},
		},
	}
}
