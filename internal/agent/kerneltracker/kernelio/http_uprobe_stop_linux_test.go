//go:build linux

package kernelio

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"golang.org/x/sys/unix"
)

func TestHTTPUprobeStopLeaseBPFMapABI(t *testing.T) {
	if got, want := binary.Size(httpUprobeProcessGeneration{}), binary.Size(bpfprog.BPFProgramHttpUprobeStopLeaseKey{}); got != want {
		t.Fatalf("stop lease key size = %d, want BPF key size %d", got, want)
	}
}

func TestHTTPUprobeStopControllerTimeoutResumesProcess(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	pid := int32(cmd.Process.Pid)
	if err := unix.Kill(int(pid), unix.SIGSTOP); err != nil {
		t.Fatalf("stop child: %v", err)
	}
	waitForTestProcessState(t, pid, true)

	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		t.Fatalf("clock_gettime: %v", err)
	}
	controller := newHTTPUprobeStopController(nil, nil)
	controller.timeout = 25 * time.Millisecond
	tracked, err := controller.track(httpUprobeAttachCandidate{
		process:       testProcessGeneration(t, pid),
		stopRequested: true,
		stopStartedNS: uint64(now.Sec)*uint64(time.Second) + uint64(now.Nsec),
	})
	if err != nil || !tracked {
		t.Fatalf("track stopped child = %v, %v", tracked, err)
	}
	waitForTestProcessState(t, pid, false)
	controller.close()
}

func TestHTTPUprobeStopControllerReleaseIsIdempotent(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	pid := int32(cmd.Process.Pid)
	if err := unix.Kill(int(pid), unix.SIGSTOP); err != nil {
		t.Fatalf("stop child: %v", err)
	}
	waitForTestProcessState(t, pid, true)
	identity := testProcessGeneration(t, pid)
	controller := newHTTPUprobeStopController(nil, nil)
	controller.timeout = time.Second
	tracked, err := controller.track(httpUprobeAttachCandidate{process: identity, stopRequested: true})
	if err != nil || !tracked {
		t.Fatalf("track stopped child = %v, %v", tracked, err)
	}

	var callers sync.WaitGroup
	for range 8 {
		callers.Go(func() { controller.release(identity, "test") })
	}
	callers.Wait()
	waitForTestProcessState(t, pid, false)
}

func TestHTTPUprobeDiscoveryFailureResumesTrackedProcess(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	pid := int32(cmd.Process.Pid)
	if err := unix.Kill(int(pid), unix.SIGSTOP); err != nil {
		t.Fatalf("stop child: %v", err)
	}
	waitForTestProcessState(t, pid, true)
	controller := newHTTPUprobeStopController(nil, nil)
	controller.timeout = time.Minute
	identity := testProcessGeneration(t, pid)
	tracked, err := controller.track(httpUprobeAttachCandidate{process: identity})
	if err != nil || !tracked {
		t.Fatalf("track stopped child = %v, %v", tracked, err)
	}

	kernelIO := &LinuxKernelIO{httpUprobeStopController: controller}
	kernelIO.failHTTPUprobeDiscovery(errors.New("reader failed"))
	kernelIO.failHTTPUprobeDiscovery(errors.New("second reader failure"))
	waitForTestProcessState(t, pid, false)
	if !kernelIO.httpUprobeDiscoveryFailed {
		t.Fatal("HTTP uprobe discovery failure was not recorded")
	}
	if controller.isActive(identity) {
		t.Fatal("stopped process remained controller-owned after fail-safe recovery")
	}
}

func testProcessGeneration(t *testing.T, pid int32) httpUprobeProcessGeneration {
	t.Helper()
	startTicks, err := readProcStartTicks(pid)
	if err != nil {
		t.Fatalf("read process start ticks: %v", err)
	}
	return httpUprobeProcessGeneration{
		TGID:          pid,
		StartBoottime: startTicks * uint64(time.Second) / linuxProcClockTicks,
	}
}

func TestProcessGenerationMatches(t *testing.T) {
	pid := int32(os.Getpid())
	startTicks, err := readProcStartTicks(pid)
	if err != nil {
		t.Fatalf("read current process start: %v", err)
	}
	identity := httpUprobeProcessGeneration{
		TGID:          pid,
		StartBoottime: startTicks * uint64(time.Second) / linuxProcClockTicks,
	}
	matched, err := processGenerationMatches(identity)
	if err != nil || !matched {
		t.Fatalf("matching process generation = %v, %v", matched, err)
	}
	identity.StartBoottime += uint64(time.Second)
	matched, err = processGenerationMatches(identity)
	if err != nil || matched {
		t.Fatalf("mismatched process generation = %v, %v", matched, err)
	}
}

func waitForTestProcessState(t *testing.T, pid int32, wantStopped bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		stopped, gone, err := processGroupStopped(pid)
		if err != nil {
			t.Fatalf("read process state: %v", err)
		}
		if gone {
			t.Fatal("child exited while checking process state")
		}
		if stopped == wantStopped {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("process stopped = %v, want %v", stopped, wantStopped)
		case <-ticker.C:
		}
	}
}
