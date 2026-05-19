package kernelio

// SampleKind* values are the ringbuf sample ABI type tags.
//
// Keep these values in sync with enum agent_sample_kind in program.bpf.c.
// KernelIO owns them because it is the raw sample boundary; decoding still
// lives in the parent bpf package.
const (
	SampleKindFork              uint32 = 1
	SampleKindCgroupMkdir       uint32 = 2
	SampleKindCgroupAttach      uint32 = 3
	SampleKindCgroupRmdir       uint32 = 4
	SampleKindExec              uint32 = 5
	SampleKindNetworkConnectV4  uint32 = 6
	SampleKindNetworkConnectV6  uint32 = 7
	SampleKindFileOpen          uint32 = 8
	SampleKindFileRemove        uint32 = 9
	SampleKindFileMove          uint32 = 10
	SampleKindFileLink          uint32 = 11
	SampleKindDNS               uint32 = 12
	SampleKindUnixSocketConnect uint32 = 13
)
