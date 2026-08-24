//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"fmt"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestLinuxKernelSampleCgroupTrackedMapOperation(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx := context.Background()
	cgroupID, err := lookupProcessCgroupID(int32(os.Getpid()), cgroupRoot)
	if err != nil {
		t.Fatalf("lookupProcessCgroupID: %v", err)
	}

	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, cgroupID); err != nil {
		t.Fatalf("PutCgroupIDInTrackedCgroupsMap: %v", err)
	}

	if err := kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(ctx, []uint64{cgroupID}); err != nil {
		t.Fatalf("DeleteCgroupIDsFromTrackedCgroupsMap: %v", err)
	}
}

func TestLinuxKernelSampleCgroupLifecycle(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)

	parentPID := int32(os.Getpid())
	parentCgroupID, err := lookupProcessCgroupID(parentPID, cgroupRoot)
	if err != nil {
		t.Fatalf("lookupProcessCgroupID: %v", err)
	}
	parentCgroupPath, err := currentCgroupPath(parentPID)
	if err != nil {
		t.Fatalf("currentCgroupPath: %v", err)
	}

	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, parentCgroupID); err != nil {
		t.Fatalf("PutCgroupIDInTrackedCgroupsMap parent cgroup: %v", err)
	}
	defer func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{parentCgroupID})
	}()

	childName := fmt.Sprintf("cicd-sensor-test-%d", time.Now().UnixNano())
	childPath := filepath.Join(parentCgroupPath, childName)
	childFullPath := mustCgroupFSPath(t, cgroupRoot, childPath)

	if err := os.Mkdir(childFullPath, 0o755); err != nil {
		t.Fatalf("Mkdir(%q): %v", childFullPath, err)
	}
	cleanupChild := true
	defer func() {
		parentProcs := mustCgroupFSPath(t, cgroupRoot, parentCgroupPath, "cgroup.procs")
		_ = os.WriteFile(parentProcs, []byte(strconv.Itoa(os.Getpid())), 0)
		if cleanupChild {
			_ = os.Remove(childFullPath)
		}
	}()

	childCgroupID, err := cgroupIDForPath(cgroupRoot, childPath)
	if err != nil {
		t.Fatalf("cgroupIDForPath(kernelIO, %q): %v", childPath, err)
	}

	waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "mkdir", func(message engineInput) bool {
		sample, ok := message.(cgroupMkdirSample)
		return ok && sample.CgroupID == childCgroupID && sample.ParentCgroupID == parentCgroupID
	})

	requireAndDeleteTrackedCgroupEntry(t, ctx, kernelIO, childCgroupID, "mkdir child")
	t.Cleanup(func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{childCgroupID})
	})

	childProcs := filepath.Join(childFullPath, "cgroup.procs")
	if err := os.WriteFile(childProcs, []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		t.Fatalf("WriteFile(%q): %v", childProcs, err)
	}

	attachChild := waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "attach child", func(message engineInput) bool {
		sample, ok := message.(cgroupAttachSample)
		return ok &&
			sample.Tgid == parentPID &&
			sample.SourceCgroupID == parentCgroupID &&
			sample.DestinationCgroupID == childCgroupID
	})
	requireTrackedCgroupEntry(t, ctx, kernelIO, childCgroupID, "attach child destination")

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := destinationTrackedState(jobID, parentCgroupID)
	effects := handleEngineInput(state, attachChild.(cgroupAttachSample))
	if owner, ok := state.jobForCgroup(childCgroupID); !ok || owner != jobID {
		t.Fatalf("attach child did not mirror destination cgroup to userspace state")
	}
	if len(effects) != 0 {
		t.Fatalf("attach child emitted effects: %#v", effects)
	}

	parentProcs := mustCgroupFSPath(t, cgroupRoot, parentCgroupPath, "cgroup.procs")
	if err := os.WriteFile(parentProcs, []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		t.Fatalf("WriteFile(%q): %v", parentProcs, err)
	}

	attachParent := waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "attach parent", func(message engineInput) bool {
		sample, ok := message.(cgroupAttachSample)
		return ok &&
			sample.Tgid == parentPID &&
			sample.SourceCgroupID == childCgroupID &&
			sample.DestinationCgroupID == parentCgroupID
	})
	if effects := handleEngineInput(state, attachParent.(cgroupAttachSample)); len(effects) != 0 {
		t.Fatalf("same-job attach back to parent emitted effects: %#v", effects)
	}

	if err := os.Remove(childFullPath); err != nil {
		t.Fatalf("Remove(%q): %v", childFullPath, err)
	}
	cleanupChild = false

	waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "rmdir", func(message engineInput) bool {
		sample, ok := message.(cgroupRmdirSample)
		return ok && sample.CgroupID == childCgroupID
	})
}

func TestLinuxKernelSampleCgroupRmdirLazyPurge(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)

	parentPID := int32(os.Getpid())
	parentCgroupID, err := lookupProcessCgroupID(parentPID, cgroupRoot)
	if err != nil {
		t.Fatalf("lookupProcessCgroupID: %v", err)
	}
	parentCgroupPath, err := currentCgroupPath(parentPID)
	if err != nil {
		t.Fatalf("currentCgroupPath: %v", err)
	}

	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, parentCgroupID); err != nil {
		t.Fatalf("PutCgroupIDInTrackedCgroupsMap parent cgroup: %v", err)
	}
	t.Cleanup(func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{parentCgroupID})
	})

	childName := fmt.Sprintf("cicd-sensor-lazy-rmdir-%d", time.Now().UnixNano())
	childPath := filepath.Join(parentCgroupPath, childName)
	childFullPath := mustCgroupFSPath(t, cgroupRoot, childPath)
	if err := os.Mkdir(childFullPath, 0o755); err != nil {
		t.Fatalf("Mkdir(%q): %v", childFullPath, err)
	}
	childCgroupID, err := cgroupIDForPath(cgroupRoot, childPath)
	if err != nil {
		t.Fatalf("cgroupIDForPath(kernelIO, %q): %v", childPath, err)
	}
	cleanupChild := true
	t.Cleanup(func() {
		if cleanupChild {
			_ = os.Remove(childFullPath)
		}
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{childCgroupID})
	})

	mkdirInput := waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "mkdir", func(message engineInput) bool {
		sample, ok := message.(cgroupMkdirSample)
		return ok && sample.CgroupID == childCgroupID && sample.ParentCgroupID == parentCgroupID
	})
	requireTrackedCgroupEntry(t, ctx, kernelIO, childCgroupID, "mkdir child")

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := destinationTrackedState(jobID, parentCgroupID)
	if effects := handleEngineInput(state, mkdirInput); len(effects) != 0 {
		t.Fatalf("mkdir mirror emitted effects: %#v", effects)
	}

	if err := os.Remove(childFullPath); err != nil {
		t.Fatalf("Remove(%q): %v", childFullPath, err)
	}
	cleanupChild = false

	rmdirInput := waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "rmdir", func(message engineInput) bool {
		sample, ok := message.(cgroupRmdirSample)
		return ok && sample.CgroupID == childCgroupID
	})
	requireTrackedCgroupEntry(t, ctx, kernelIO, childCgroupID, "removed pending child")

	if effects := handleEngineInput(state, rmdirInput); len(effects) != 0 {
		t.Fatalf("non-final rmdir emitted effects: %#v", effects)
	}
	if owner, ok := state.jobForCgroup(childCgroupID); !ok || owner != jobID {
		t.Fatalf("removed pending child owner = %v ok=%v, want %v true", owner, ok, jobID)
	}

	state.cgroupsByJob[jobID][childCgroupID].RemovedAt = time.Now().UTC().Add(-cgroupRemovalGracePeriod - time.Second)
	effects := handleEngineInput(state, commandPurgeExpiredTrackingState{})
	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	engine.jobTracking = state
	engine.runEngineEffects(ctx, effects)

	if ok, err := kernelIO.TestOnlyLookupCgroupIDInTrackedCgroupsMap(ctx, childCgroupID); err != nil {
		t.Fatalf("lookup purged child cgroup: %v", err)
	} else if ok {
		t.Fatal("child cgroup remained in tracked_cgroups after purge")
	}
}

func TestLinuxKernelSampleCgroupFinalRmdirRemoveJobCleanup(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)

	parentPID := int32(os.Getpid())
	parentCgroupPath, err := currentCgroupPath(parentPID)
	if err != nil {
		t.Fatalf("currentCgroupPath: %v", err)
	}

	childName := fmt.Sprintf("cicd-sensor-final-rmdir-%d", time.Now().UnixNano())
	childPath := filepath.Join(parentCgroupPath, childName)
	childFullPath := mustCgroupFSPath(t, cgroupRoot, childPath)
	if err := os.Mkdir(childFullPath, 0o755); err != nil {
		t.Fatalf("Mkdir(%q): %v", childFullPath, err)
	}
	childCgroupID, err := cgroupIDForPath(cgroupRoot, childPath)
	if err != nil {
		t.Fatalf("cgroupIDForPath(kernelIO, %q): %v", childPath, err)
	}
	cleanupChild := true
	t.Cleanup(func() {
		if cleanupChild {
			_ = os.Remove(childFullPath)
		}
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{childCgroupID})
	})

	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, childCgroupID); err != nil {
		t.Fatalf("PutCgroupIDInTrackedCgroupsMap child cgroup: %v", err)
	}
	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := destinationTrackedState(jobID, childCgroupID)

	if err := os.Remove(childFullPath); err != nil {
		t.Fatalf("Remove(%q): %v", childFullPath, err)
	}
	cleanupChild = false

	rmdirInput := waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "final rmdir", func(message engineInput) bool {
		sample, ok := message.(cgroupRmdirSample)
		return ok && sample.CgroupID == childCgroupID
	})
	requireTrackedCgroupEntry(t, ctx, kernelIO, childCgroupID, "final removed child")

	effects := handleEngineInput(state, rmdirInput)
	assertEffectOrder(t, effects, notifyJobEnded{})

	removeEffects := handleEngineInput(state, commandRemoveJob{JobID: jobID})
	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	engine.jobTracking = state
	engine.runEngineEffects(ctx, removeEffects)

	if ok, err := kernelIO.TestOnlyLookupCgroupIDInTrackedCgroupsMap(ctx, childCgroupID); err != nil {
		t.Fatalf("lookup final removed child cgroup: %v", err)
	} else if ok {
		t.Fatal("final removed child cgroup remained in tracked_cgroups after RemoveJob")
	}
}

func TestLinuxKernelSampleCgroupLivenessReconciliation(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	parentPID := int32(os.Getpid())
	parentCgroupPath, err := currentCgroupPath(parentPID)
	if err != nil {
		t.Fatalf("currentCgroupPath: %v", err)
	}

	childName := fmt.Sprintf("cicd-sensor-liveness-%d", time.Now().UnixNano())
	childPath := filepath.Join(parentCgroupPath, childName)
	childFullPath := mustCgroupFSPath(t, cgroupRoot, childPath)
	if err := os.Mkdir(childFullPath, 0o755); err != nil {
		t.Fatalf("Mkdir(%q): %v", childFullPath, err)
	}
	cleanupChild := true
	t.Cleanup(func() {
		if cleanupChild {
			_ = os.Remove(childFullPath)
		}
	})

	childCgroupID, err := cgroupIDForPath(cgroupRoot, childPath)
	if err != nil {
		t.Fatalf("cgroupIDForPath(%q): %v", childPath, err)
	}
	liveSnapshot, err := scanLiveCgroupIDs(cgroupRoot)
	if err != nil {
		t.Fatalf("scanLiveCgroupIDs live child: %v", err)
	}
	if _, ok := liveSnapshot.LiveCgroupIDs[childCgroupID]; !ok {
		t.Fatalf("live child cgroup %d was not found by cgroup liveness scan", childCgroupID)
	}

	scanStartedAt := time.Now().UTC()
	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.registerJob(jobID, defaultEventRecordBufferSize)
	state.bindAt(jobID, childCgroupID, scanStartedAt.Add(-time.Second))

	if err := os.Remove(childFullPath); err != nil {
		t.Fatalf("Remove(%q): %v", childFullPath, err)
	}
	cleanupChild = false

	missingSnapshot, err := scanLiveCgroupIDs(cgroupRoot)
	if err != nil {
		t.Fatalf("scanLiveCgroupIDs missing child: %v", err)
	}
	if _, ok := missingSnapshot.LiveCgroupIDs[childCgroupID]; ok {
		t.Fatalf("removed child cgroup %d was still found by cgroup liveness scan", childCgroupID)
	}

	effects := handleEngineInput(state, commandReconcileCgroupLiveness{
		ScanStartedAt: scanStartedAt,
		CheckedAt:     time.Now().UTC(),
		LiveCgroupIDs: missingSnapshot.LiveCgroupIDs,
	})
	assertEffectOrder(t, effects, notifyJobEnded{})
}

func TestLinuxKernelSampleCgroupAttachExternal(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)

	parentPID := int32(os.Getpid())
	parentCgroupID, err := lookupProcessCgroupID(parentPID, cgroupRoot)
	if err != nil {
		t.Fatalf("lookupProcessCgroupID: %v", err)
	}
	parentCgroupPath, err := currentCgroupPath(parentPID)
	if err != nil {
		t.Fatalf("currentCgroupPath: %v", err)
	}

	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, parentCgroupID); err != nil {
		t.Fatalf("PutCgroupIDInTrackedCgroupsMap parent cgroup: %v", err)
	}
	t.Cleanup(func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{parentCgroupID})
	})

	trackedName := fmt.Sprintf("cicd-sensor-escape-tracked-%d", time.Now().UnixNano())
	trackedPath := filepath.Join(parentCgroupPath, trackedName)
	trackedFullPath := mustCgroupFSPath(t, cgroupRoot, trackedPath)
	if err := os.Mkdir(trackedFullPath, 0o755); err != nil {
		t.Fatalf("Mkdir(%q): %v", trackedFullPath, err)
	}

	untrackedName := fmt.Sprintf("cicd-sensor-escape-untracked-%d", time.Now().UnixNano())
	untrackedPath := filepath.Join(parentCgroupPath, untrackedName)
	untrackedFullPath := mustCgroupFSPath(t, cgroupRoot, untrackedPath)
	if err := os.Mkdir(untrackedFullPath, 0o755); err != nil {
		_ = os.Remove(trackedFullPath)
		t.Fatalf("Mkdir(%q): %v", untrackedFullPath, err)
	}

	t.Cleanup(func() {
		parentProcs := mustCgroupFSPath(t, cgroupRoot, parentCgroupPath, "cgroup.procs")
		_ = os.WriteFile(parentProcs, []byte(strconv.Itoa(os.Getpid())), 0)
		_ = os.Remove(untrackedFullPath)
		_ = os.Remove(trackedFullPath)
	})

	trackedCgroupID, err := cgroupIDForPath(cgroupRoot, trackedPath)
	if err != nil {
		t.Fatalf("cgroupIDForPath(kernelIO, %q): %v", trackedPath, err)
	}
	untrackedCgroupID, err := cgroupIDForPath(cgroupRoot, untrackedPath)
	if err != nil {
		t.Fatalf("cgroupIDForPath(kernelIO, %q): %v", untrackedPath, err)
	}

	waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "tracked mkdir", func(message engineInput) bool {
		sample, ok := message.(cgroupMkdirSample)
		return ok && sample.CgroupID == trackedCgroupID
	})
	waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "untracked mkdir", func(message engineInput) bool {
		sample, ok := message.(cgroupMkdirSample)
		return ok && sample.CgroupID == untrackedCgroupID
	})

	requireTrackedCgroupEntry(t, ctx, kernelIO, trackedCgroupID, "tracked mkdir child")
	t.Cleanup(func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{trackedCgroupID})
	})
	requireAndDeleteTrackedCgroupEntry(t, ctx, kernelIO, untrackedCgroupID, "mkdir destination")
	t.Cleanup(func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{untrackedCgroupID})
	})

	trackedProcs := filepath.Join(trackedFullPath, "cgroup.procs")
	if err := os.WriteFile(trackedProcs, []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		t.Fatalf("WriteFile(%q): %v", trackedProcs, err)
	}
	waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "attach tracked", func(message engineInput) bool {
		sample, ok := message.(cgroupAttachSample)
		return ok &&
			sample.Tgid == parentPID &&
			sample.SourceCgroupID == parentCgroupID &&
			sample.DestinationCgroupID == trackedCgroupID
	})

	untrackedProcs := filepath.Join(untrackedFullPath, "cgroup.procs")
	if err := os.WriteFile(untrackedProcs, []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		t.Fatalf("WriteFile(%q): %v", untrackedProcs, err)
	}
	message := waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "escape attach", func(message engineInput) bool {
		sample, ok := message.(cgroupAttachSample)
		return ok &&
			sample.Tgid == parentPID &&
			sample.SourceCgroupID == trackedCgroupID &&
			sample.DestinationCgroupID == untrackedCgroupID
	})
	requireTrackedCgroupEntry(t, ctx, kernelIO, untrackedCgroupID, "escape destination")

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := destinationTrackedState(jobID, trackedCgroupID)

	effects := handleEngineInput(state, message.(cgroupAttachSample))
	if owner, ok := state.jobForCgroup(trackedCgroupID); !ok || owner != jobID {
		t.Fatalf("tracking lost source cgroup binding on escape")
	}
	if owner, ok := state.jobForCgroup(untrackedCgroupID); !ok || owner != jobID {
		t.Fatalf("escape did not extend tracking to destination cgroup")
	}
	if !testHasTrackedCgroups(state, jobID) {
		t.Fatalf("tracking lost job during escape handling")
	}
	if len(effects) != 0 {
		t.Fatalf("escape emitted effects: %#v", effects)
	}
}

func TestLinuxKernelSampleCgroupAttachAcrossTrackedJobs(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)

	parentPID := int32(os.Getpid())
	parentCgroupPath, err := currentCgroupPath(parentPID)
	if err != nil {
		t.Fatalf("currentCgroupPath: %v", err)
	}

	sourceName := fmt.Sprintf("cicd-sensor-cross-source-%d", time.Now().UnixNano())
	sourcePath := filepath.Join(parentCgroupPath, sourceName)
	sourceFullPath := mustCgroupFSPath(t, cgroupRoot, sourcePath)
	if err := os.Mkdir(sourceFullPath, 0o755); err != nil {
		t.Fatalf("Mkdir(%q): %v", sourceFullPath, err)
	}

	destinationName := fmt.Sprintf("cicd-sensor-cross-destination-%d", time.Now().UnixNano())
	destinationPath := filepath.Join(parentCgroupPath, destinationName)
	destinationFullPath := mustCgroupFSPath(t, cgroupRoot, destinationPath)
	if err := os.Mkdir(destinationFullPath, 0o755); err != nil {
		_ = os.Remove(sourceFullPath)
		t.Fatalf("Mkdir(%q): %v", destinationFullPath, err)
	}
	t.Cleanup(func() {
		_ = os.Remove(destinationFullPath)
		_ = os.Remove(sourceFullPath)
	})

	sourceCgroupID, err := cgroupIDForPath(cgroupRoot, sourcePath)
	if err != nil {
		t.Fatalf("cgroupIDForPath(kernelIO, %q): %v", sourcePath, err)
	}
	destinationCgroupID, err := cgroupIDForPath(cgroupRoot, destinationPath)
	if err != nil {
		t.Fatalf("cgroupIDForPath(kernelIO, %q): %v", destinationPath, err)
	}

	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, sourceCgroupID); err != nil {
		t.Fatalf("put source cgroup: %v", err)
	}
	t.Cleanup(func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{sourceCgroupID})
	})
	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, destinationCgroupID); err != nil {
		t.Fatalf("put destination cgroup: %v", err)
	}
	t.Cleanup(func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{destinationCgroupID})
	})

	cmd := exec.Command("/bin/sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep child: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	childPID := int32(cmd.Process.Pid)
	sourceProcs := filepath.Join(sourceFullPath, "cgroup.procs")
	if err := os.WriteFile(sourceProcs, []byte(strconv.Itoa(int(childPID))), 0); err != nil {
		t.Fatalf("attach child to source cgroup: %v", err)
	}

	destinationProcs := filepath.Join(destinationFullPath, "cgroup.procs")
	if err := os.WriteFile(destinationProcs, []byte(strconv.Itoa(int(childPID))), 0); err != nil {
		t.Fatalf("attach child to destination cgroup: %v", err)
	}

	message := waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "cross-job attach", func(message engineInput) bool {
		sample, ok := message.(cgroupAttachSample)
		return ok &&
			sample.Tgid == childPID &&
			sample.SourceCgroupID == sourceCgroupID &&
			sample.DestinationCgroupID == destinationCgroupID
	})
	requireTrackedCgroupEntry(t, ctx, kernelIO, sourceCgroupID, "cross-job source")
	requireTrackedCgroupEntry(t, ctx, kernelIO, destinationCgroupID, "cross-job destination")

	sourceJobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	destinationJobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "456")
	state := destinationTrackedState(sourceJobID, sourceCgroupID)
	state.registerJob(destinationJobID, defaultEventRecordBufferSize)
	state.bind(destinationJobID, destinationCgroupID)

	effects := handleEngineInput(state, message.(cgroupAttachSample))
	if owner, ok := state.jobForCgroup(sourceCgroupID); !ok || owner != sourceJobID {
		t.Fatalf("source cgroup owner changed on cross-job attach")
	}
	if owner, ok := state.jobForCgroup(destinationCgroupID); !ok || owner != destinationJobID {
		t.Fatalf("destination cgroup owner changed on cross-job attach")
	}
	if len(effects) != 0 {
		t.Fatalf("cross-job attach emitted effects: %#v", effects)
	}
}

func TestLinuxKernelSampleCgroupStagingMatchTracksAndConsumesStaging(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)

	parentPID := int32(os.Getpid())
	parentCgroupID, err := lookupProcessCgroupID(parentPID, cgroupRoot)
	if err != nil {
		t.Fatalf("lookupProcessCgroupID: %v", err)
	}
	parentCgroupPath, err := currentCgroupPath(parentPID)
	if err != nil {
		t.Fatalf("currentCgroupPath: %v", err)
	}

	basename := fmt.Sprintf("docker-cicd-staged-%d.scope", time.Now().UnixNano())
	if err := kernelIO.PutCgroupBasenameInStagingMap(ctx, basename); err != nil {
		t.Fatalf("PutCgroupBasenameInStagingMap: %v", err)
	}
	t.Cleanup(func() {
		_ = kernelIO.DeleteCgroupBasenamesFromStagingMap(context.Background(), []string{basename})
	})

	childPath := filepath.Join(parentCgroupPath, basename)
	childFullPath := mustCgroupFSPath(t, cgroupRoot, childPath)
	if err := os.Mkdir(childFullPath, 0o755); err != nil {
		t.Fatalf("Mkdir(%q): %v", childFullPath, err)
	}
	cleanupChild := true
	t.Cleanup(func() {
		if cleanupChild {
			_ = os.Remove(childFullPath)
		}
	})

	childCgroupID, err := cgroupIDForPath(cgroupRoot, childPath)
	if err != nil {
		t.Fatalf("cgroupIDForPath(kernelIO, %q): %v", childPath, err)
	}

	waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "staging matched mkdir", func(message engineInput) bool {
		sample, ok := message.(cgroupMkdirSample)
		return ok &&
			sample.CgroupID == childCgroupID &&
			sample.ParentCgroupID == parentCgroupID &&
			sample.StagingMatched
	})

	requireAndDeleteTrackedCgroupEntry(t, ctx, kernelIO, childCgroupID, "staging matched child")
	if ok, err := kernelIO.TestOnlyLookupCgroupBasenameInStagingMap(ctx, basename); err != nil {
		t.Fatalf("lookup consumed staging basename: %v", err)
	} else if ok {
		t.Fatalf("staging basename %q was not consumed by cgroup_mkdir", basename)
	}

	if err := os.Remove(childFullPath); err != nil {
		t.Fatalf("Remove(%q): %v", childFullPath, err)
	}
	cleanupChild = false

	if err := os.Mkdir(childFullPath, 0o755); err != nil {
		t.Fatalf("Mkdir second %q: %v", childFullPath, err)
	}
	cleanupChild = true

	if message, ok := findEngineInput(kernelTracker.inputCh, 500*time.Millisecond, func(message engineInput) bool {
		sample, ok := message.(cgroupMkdirSample)
		return ok && sample.CgroupPath == childPath && sample.StagingMatched
	}); ok {
		t.Fatalf("staging entry was reused after kernel consume: %#v", message)
	}
}
