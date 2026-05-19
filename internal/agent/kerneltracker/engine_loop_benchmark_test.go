package kerneltracker

import (
	"strconv"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// BenchmarkHandleEngineInput_EmitEventRecord exercises a single FileOpen event on a
// minimal state (1 job / 1 cgroup / 1 process). Use it as a smallest-case
// reference; the scale-independence claim is in
// BenchmarkHandleEngineInput_FileOpen_LargeProcessContext.
func BenchmarkHandleEngineInput_EmitEventRecord(b *testing.B) {
	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newTrackedState(jobID, 42)
	identity := processIdentity{PID: 100, StartBoottime: 1}
	state.recordExec(jobID, identity, "", nil, 0)
	sample := fileOpenSample{
		Identity: identity,
		CgroupID: 42,
		Path:     "/workspace/file.txt",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handleEngineInput(state, sample)
	}
}

// BenchmarkHandleEngineInput_RegisterJobBindCgroupRemoveJob measures the
// RegisterJob + BindCgroup + RemoveJob cycle. Allocation here is dominated
// by the per-Job event channel pre-allocation, not by state clone. It is
// retained as a sanity check for Job lifecycle cost.
func BenchmarkHandleEngineInput_RegisterJobBindCgroupRemoveJob(b *testing.B) {
	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	startReply := make(chan registerJobReply, 1)
	startInput := commandRegisterJob{
		JobID: jobID,
		Reply: startReply,
	}
	bindReply := make(chan error, 1)
	bindInput := commandBindCgroup{JobID: jobID, CgroupID: 42, Reply: bindReply}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := newJobTrackingState()
		handleEngineInput(state, startInput)
		handleEngineInput(state, bindInput)
		handleEngineInput(state, commandRemoveJob{JobID: jobID})
	}
}

// BenchmarkHandleEngineInput_FileOpen_LargeProcessContext stresses handleEngineInput on a
// realistic process state: many jobs each tracking many processes. The event
// cost should stay O(1) with respect to state size now that state clone-on-
// write has been removed.
func BenchmarkHandleEngineInput_FileOpen_LargeProcessContext(b *testing.B) {
	cases := []struct {
		name        string
		numJobs     int
		perJobProcs int
	}{
		{name: "jobs=10/procs=10", numJobs: 10, perJobProcs: 10},
		{name: "jobs=100/procs=100", numJobs: 100, perJobProcs: 100},
		{name: "jobs=1000/procs=10", numJobs: 1000, perJobProcs: 10},
	}

	for _, benchCase := range cases {
		b.Run(benchCase.name, func(b *testing.B) {
			state := newJobTrackingState()
			var targetCgroup uint64
			var targetIdentity processIdentity

			for j := 0; j < benchCase.numJobs; j++ {
				jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", strconv.Itoa(j))
				cgroupID := uint64(1000 + j)
				state.registerJob(jobID, defaultEventRecordBufferSize)
				state.bind(jobID, cgroupID)
				for p := 0; p < benchCase.perJobProcs; p++ {
					identity := processIdentity{
						PID:           int32(10000 + j*benchCase.perJobProcs + p),
						StartBoottime: uint64(p + 1),
					}
					state.recordExec(jobID, identity, "", nil, 0)
					if j == 0 && p == 0 {
						targetCgroup = cgroupID
						targetIdentity = identity
					}
				}
			}

			sample := fileOpenSample{
				Identity: targetIdentity,
				CgroupID: targetCgroup,
				Path:     "/workspace/file.txt",
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				handleEngineInput(state, sample)
			}
		})
	}
}
