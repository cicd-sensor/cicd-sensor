//go:build linux && bpf_integration

package kernelio

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const httpUprobeStopRecoveryHelperEnv = "HTTP_UPROBE_STOP_RECOVERY_HELPER"
const httpUprobeStopRecoveryPIDPrefix = "HTTP_UPROBE_STOP_PID="

func TestLinuxHTTPUprobeStartupRecoversStoppedProcess(t *testing.T) {
	if os.Getenv(httpUprobeStopRecoveryHelperEnv) == "1" {
		runHTTPUprobeStopRecoveryHelper(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestLinuxHTTPUprobeStartupRecoversStoppedProcess$")
	cmd.Env = append(os.Environ(), httpUprobeStopRecoveryHelperEnv+"=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run recovery helper: %v: %s", err, output)
	}
	pidText := ""
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, httpUprobeStopRecoveryPIDPrefix) {
			pidText = strings.TrimPrefix(line, httpUprobeStopRecoveryPIDPrefix)
			break
		}
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil {
		t.Fatalf("parse stopped child pid %q: %v", output, err)
	}
	t.Cleanup(func() {
		_ = unix.Kill(pid, unix.SIGCONT)
		_ = unix.Kill(pid, unix.SIGKILL)
	})
	waitForIntegrationProcessStopped(t, int32(pid), true)

	config := testLinuxConfig(t)
	config.EnableHTTPRequest = false
	kernelIO, err := NewLinux(nil, config)
	if err != nil {
		t.Fatalf("start KernelIO recovery: %v", err)
	}
	t.Cleanup(func() { _ = kernelIO.Close() })
	waitForIntegrationProcessStopped(t, int32(pid), false)
}

func TestLinuxHTTPUprobeSafetySweepResumesExpiredLease(t *testing.T) {
	config := testLinuxConfig(t)
	config.EnableHTTPRequest = true
	kernelIO, err := NewLinux(nil, config)
	if err != nil {
		t.Fatalf("start KernelIO: %v", err)
	}
	t.Cleanup(func() { _ = kernelIO.Close() })

	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	pid := int32(cmd.Process.Pid)
	identity := testProcessGeneration(t, pid)
	nowNS, err := monotonicNowNS()
	if err != nil {
		t.Fatalf("read monotonic clock: %v", err)
	}
	startedNS := nowNS - uint64(httpUprobeStopSafetyPeriod)
	if err := kernelIO.objs.HttpUprobeStopLeases.Put(identity, startedNS); err != nil {
		t.Fatalf("insert expired stop lease: %v", err)
	}
	if err := unix.Kill(int(pid), unix.SIGSTOP); err != nil {
		t.Fatalf("stop child: %v", err)
	}
	waitForIntegrationProcessStopped(t, pid, true)

	kernelIO.httpUprobeWorker.resumeExpiredStopLeases()
	waitForIntegrationProcessStopped(t, pid, false)
	var remaining uint64
	if err := kernelIO.objs.HttpUprobeStopLeases.Lookup(identity, &remaining); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("expired stop lease lookup error = %v, want ErrKeyNotExist", err)
	}
}

func runHTTPUprobeStopRecoveryHelper(t *testing.T) {
	config := testLinuxConfig(t)
	config.EnableHTTPRequest = true
	kernelIO, err := NewLinux(nil, config)
	if err != nil {
		t.Fatalf("start helper KernelIO: %v", err)
	}

	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	pid := int32(cmd.Process.Pid)
	startTicks, err := readProcStartTicks(pid)
	if err != nil {
		t.Fatalf("read child start time: %v", err)
	}
	identity := httpUprobeProcessGeneration{
		TGID:          pid,
		StartBoottime: startTicks * uint64(time.Second) / linuxProcClockTicks,
	}
	if err := kernelIO.objs.HttpUprobeStopLeases.Put(identity, uint64(1)); err != nil {
		t.Fatalf("insert recovery lease: %v", err)
	}
	if err := unix.Kill(int(pid), unix.SIGSTOP); err != nil {
		t.Fatalf("stop child: %v", err)
	}
	waitForIntegrationProcessStopped(t, pid, true)
	fmt.Printf("%s%d\n", httpUprobeStopRecoveryPIDPrefix, pid)
	os.Exit(0) // Simulate Agent death: close FDs without running KernelIO.Close.
}

func waitForIntegrationProcessStopped(t *testing.T, pid int32, want bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stopped, gone, err := processGroupStopped(pid)
		if err != nil {
			t.Fatalf("read child state: %v", err)
		}
		if gone {
			t.Fatal("child exited before recovery completed")
		}
		if stopped == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("child stopped = %v, want %v", !want, want)
}
