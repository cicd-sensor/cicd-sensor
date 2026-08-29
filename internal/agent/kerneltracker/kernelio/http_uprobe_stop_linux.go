//go:build linux

package kernelio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	httpUprobeBPFFSPinPath     = "/sys/fs/bpf/cicd-sensor"
	httpUprobeStopMapName      = "http_uprobe_stop_leases"
	httpUprobeStopSafetyPeriod = 5 * time.Second
	linuxProcClockTicks        = 100
)

type httpUprobeProcessGeneration struct {
	TGID          int32
	_             uint32
	StartBoottime uint64
}

type httpUprobeStopLease struct {
	identity  httpUprobeProcessGeneration
	startedNS uint64
}

func monotonicNowNS() (uint64, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return 0, err
	}
	return uint64(now.Sec)*uint64(time.Second) + uint64(now.Nsec), nil
}

func httpUprobeStopLeaseExpired(nowNS, startedNS uint64) bool {
	if startedNS == 0 {
		return true
	}
	if nowNS <= startedNS {
		return false
	}
	return nowNS-startedNS >= uint64(httpUprobeStopSafetyPeriod)
}

// resumeHTTPUprobeProcess opens a pidfd before the procfs generation check so
// PID reuse cannot redirect SIGCONT. A gone or reused process needs no signal.
func resumeHTTPUprobeProcess(identity httpUprobeProcessGeneration) error {
	pidfd, err := unix.PidfdOpen(int(identity.TGID), 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open pidfd for stopped process %d: %w", identity.TGID, err)
	}
	defer unix.Close(pidfd)

	matches, err := processGenerationMatches(identity)
	if err != nil {
		if processIsGone(err) {
			return nil
		}
		return fmt.Errorf("verify stopped process %d generation: %w", identity.TGID, err)
	}
	if !matches {
		return nil
	}
	if err := unix.PidfdSendSignal(pidfd, unix.SIGCONT, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("resume stopped process %d: %w", identity.TGID, err)
	}
	return nil
}

func deleteHTTPUprobeStopLease(leaseMap *ebpf.Map, identity httpUprobeProcessGeneration) error {
	if leaseMap == nil {
		return nil
	}
	if err := leaseMap.Delete(identity); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// recoverHTTPUprobeStopLeases runs before the mapping hook is attached. It
// resumes only the process generation recorded by BPF, then removes every
// lease.
func recoverHTTPUprobeStopLeases(leaseMap *ebpf.Map) error {
	if leaseMap == nil {
		return nil
	}
	iterator := leaseMap.Iterate()
	var identity httpUprobeProcessGeneration
	var stoppedAtNS uint64
	for iterator.Next(&identity, &stoppedAtNS) {
		if err := resumeHTTPUprobeProcess(identity); err != nil {
			return err
		}
		if err := deleteHTTPUprobeStopLease(leaseMap, identity); err != nil {
			return fmt.Errorf("delete HTTP uprobe stop lease for %d: %w", identity.TGID, err)
		}
	}
	if err := iterator.Err(); err != nil {
		return fmt.Errorf("iterate HTTP uprobe stop leases: %w", err)
	}
	return nil
}

// recoverAndUnpinHTTPUprobeStopLeases keeps --enable-http-request=false safe after
// a prior enabled Agent exited while a process stop lease was still pinned.
func recoverAndUnpinHTTPUprobeStopLeases() error {
	pinnedPath := filepath.Join(httpUprobeBPFFSPinPath, httpUprobeStopMapName)
	leaseMap, err := ebpf.LoadPinnedMap(pinnedPath, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open pinned HTTP uprobe stop leases: %w", err)
	}
	defer leaseMap.Close()
	if err := recoverHTTPUprobeStopLeases(leaseMap); err != nil {
		return err
	}
	if err := leaseMap.Unpin(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unpin HTTP uprobe stop leases: %w", err)
	}
	return nil
}

func processGenerationMatches(identity httpUprobeProcessGeneration) (bool, error) {
	startTicks, err := readProcStartTicks(identity.TGID)
	if err != nil {
		return false, err
	}
	seconds := identity.StartBoottime / uint64(time.Second)
	nanoseconds := identity.StartBoottime % uint64(time.Second)
	wantTicks := seconds*linuxProcClockTicks + nanoseconds*linuxProcClockTicks/uint64(time.Second)
	return tickDistance(startTicks, wantTicks) <= 1, nil
}

func tickDistance(left, right uint64) uint64 {
	if left >= right {
		return left - right
	}
	return right - left
}

func readProcStartTicks(pid int32) (uint64, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "stat"))
	if err != nil {
		return 0, err
	}
	closeParen := strings.LastIndexByte(string(raw), ')')
	if closeParen < 0 || closeParen+2 >= len(raw) {
		return 0, fmt.Errorf("invalid proc stat for pid %d", pid)
	}
	fields := strings.Fields(string(raw[closeParen+2:]))
	const startTimeIndexAfterComm = 19 // field 22, with field 3 at index 0
	if len(fields) <= startTimeIndexAfterComm {
		return 0, fmt.Errorf("short proc stat for pid %d", pid)
	}
	startTicks, err := strconv.ParseUint(fields[startTimeIndexAfterComm], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse proc start time for pid %d: %w", pid, err)
	}
	return startTicks, nil
}

func processGroupStopped(pid int32) (stopped bool, gone bool, err error) {
	taskDir := filepath.Join("/proc", strconv.Itoa(int(pid)), "task")
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		if processIsGone(err) {
			return false, true, nil
		}
		return false, false, err
	}
	if len(entries) == 0 {
		return false, true, nil
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(taskDir, entry.Name(), "stat"))
		if err != nil {
			if processIsGone(err) {
				continue
			}
			return false, false, err
		}
		closeParen := strings.LastIndexByte(string(raw), ')')
		if closeParen < 0 || closeParen+2 >= len(raw) {
			return false, false, fmt.Errorf("invalid task stat for pid %d task %s", pid, entry.Name())
		}
		state := raw[closeParen+2]
		if state != 'T' && state != 't' {
			return false, false, nil
		}
	}
	return true, false, nil
}
