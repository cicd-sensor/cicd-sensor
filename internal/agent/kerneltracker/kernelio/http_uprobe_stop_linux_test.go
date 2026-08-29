//go:build linux

package kernelio

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
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

func TestHTTPUprobeStopLeaseExpired(t *testing.T) {
	now := uint64(10 * time.Second)
	for _, test := range []struct {
		name      string
		startedNS uint64
		want      bool
	}{
		{name: "zero timestamp is invalid and expires", want: true},
		{name: "younger than safety period remains", startedNS: now - uint64(httpUprobeStopSafetyPeriod) + 1},
		{name: "exact safety period expires", startedNS: now - uint64(httpUprobeStopSafetyPeriod), want: true},
		{name: "older than safety period expires", startedNS: 1, want: true},
		{name: "future timestamp remains", startedNS: now + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := httpUprobeStopLeaseExpired(now, test.startedNS); got != test.want {
				t.Fatalf("httpUprobeStopLeaseExpired(%d, %d) = %v, want %v", now, test.startedNS, got, test.want)
			}
		})
	}
}

func TestResumeHTTPUprobeProcess(t *testing.T) {
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
	if err := resumeHTTPUprobeProcess(identity); err != nil {
		t.Fatalf("resume stopped child: %v", err)
	}
	waitForTestProcessState(t, pid, false)
}

func TestResumeHTTPUprobeProcessDoesNotSignalReusedPID(t *testing.T) {
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
	identity.StartBoottime += uint64(time.Second)
	if err := resumeHTTPUprobeProcess(identity); err != nil {
		t.Fatalf("ignore mismatched process generation: %v", err)
	}
	waitForTestProcessState(t, pid, true)
	_ = unix.Kill(int(pid), unix.SIGCONT)
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
