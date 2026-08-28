//go:build linux

package kernelio

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	httpUprobeBPFFSPinPath = "/sys/fs/bpf/cicd-sensor"
	httpUprobeStopMapName  = "http_uprobe_stop_leases"
	httpUprobeStopTimeout  = 500 * time.Millisecond
	linuxProcClockTicks    = 100
)

type httpUprobeProcessGeneration struct {
	TGID          int32
	_             uint32
	StartBoottime uint64
}

type activeHTTPUprobeStop struct {
	pidfd int
	timer *time.Timer
}

// httpUprobeStopController owns only the bounded SIGSTOP/SIGCONT lifecycle.
// ELF classification and uprobe links stay on the single HTTP uprobe worker.
type httpUprobeStopController struct {
	logger   *slog.Logger
	leaseMap *ebpf.Map
	timeout  time.Duration

	mu     sync.Mutex
	active map[httpUprobeProcessGeneration]*activeHTTPUprobeStop
}

func newHTTPUprobeStopController(logger *slog.Logger, leaseMap *ebpf.Map) *httpUprobeStopController {
	return &httpUprobeStopController{
		logger:   logger,
		leaseMap: leaseMap,
		timeout:  httpUprobeStopTimeout,
		active:   make(map[httpUprobeProcessGeneration]*activeHTTPUprobeStop),
	}
}

// track starts an independent best-effort pause timer after the BPF hook
// successfully requested SIGSTOP. A false result means the process was resumed.
func (controller *httpUprobeStopController) track(candidate httpUprobeAttachCandidate) (bool, error) {
	identity := candidate.process
	pidfd, err := unix.PidfdOpen(int(identity.TGID), 0)
	if err != nil {
		controller.resumeWithoutPidfd(identity)
		return false, fmt.Errorf("open pidfd for stopped process %d: %w", identity.TGID, err)
	}

	controller.mu.Lock()
	if _, exists := controller.active[identity]; exists {
		controller.mu.Unlock()
		_ = unix.Close(pidfd)
		return true, nil
	}
	entry := &activeHTTPUprobeStop{pidfd: pidfd}
	controller.active[identity] = entry
	remaining := controller.remaining(candidate.stopStartedNS)
	entry.timer = time.AfterFunc(remaining, func() {
		controller.release(identity, "timeout")
	})
	controller.mu.Unlock()
	return true, nil
}

func (controller *httpUprobeStopController) remaining(startedNS uint64) time.Duration {
	if startedNS == 0 {
		return controller.timeout
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return controller.timeout
	}
	nowNS := uint64(now.Sec)*uint64(time.Second) + uint64(now.Nsec)
	if nowNS <= startedNS {
		return controller.timeout
	}
	elapsed := time.Duration(nowNS - startedNS)
	if elapsed >= controller.timeout {
		return 0
	}
	return controller.timeout - elapsed
}

// release is safe from the worker, queue-failure path, timeout callback, and
// shutdown. Exactly one caller owns the pidfd and sends SIGCONT.
func (controller *httpUprobeStopController) release(identity httpUprobeProcessGeneration, reason string) {
	controller.mu.Lock()
	entry, ok := controller.active[identity]
	if ok {
		delete(controller.active, identity)
		if entry.timer != nil {
			entry.timer.Stop()
		}
	}
	controller.mu.Unlock()
	if !ok {
		return
	}

	resumeErr := unix.PidfdSendSignal(entry.pidfd, unix.SIGCONT, nil, 0)
	_ = unix.Close(entry.pidfd)
	if resumeErr == nil || errors.Is(resumeErr, unix.ESRCH) {
		controller.deleteLease(identity)
	} else {
		controller.warn("http_uprobe_resume_failed", "tgid", identity.TGID, "reason", reason, "error", resumeErr)
	}
	if reason == "timeout" {
		controller.warn("http_uprobe_stop_timeout", "tgid", identity.TGID)
	}
}

func (controller *httpUprobeStopController) resumeWithoutPidfd(identity httpUprobeProcessGeneration) {
	matches, err := processGenerationMatches(identity)
	if err != nil {
		if processIsGone(err) {
			controller.deleteLease(identity)
			return
		}
		controller.warn("http_uprobe_resume_failed", "tgid", identity.TGID, "reason", "pidfd_open_failed_generation_check", "error", err)
		return
	}
	if !matches {
		controller.deleteLease(identity)
		return
	}
	if err := unix.Kill(int(identity.TGID), unix.SIGCONT); err != nil && !errors.Is(err, unix.ESRCH) {
		controller.warn("http_uprobe_resume_failed", "tgid", identity.TGID, "reason", "pidfd_open_failed", "error", err)
		return
	}
	controller.deleteLease(identity)
}

func (controller *httpUprobeStopController) close() {
	controller.mu.Lock()
	identities := make([]httpUprobeProcessGeneration, 0, len(controller.active))
	for identity := range controller.active {
		identities = append(identities, identity)
	}
	controller.mu.Unlock()
	for _, identity := range identities {
		controller.release(identity, "shutdown")
	}
}

func (controller *httpUprobeStopController) isActive(identity httpUprobeProcessGeneration) bool {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	_, ok := controller.active[identity]
	return ok
}

func (controller *httpUprobeStopController) deleteLease(identity httpUprobeProcessGeneration) {
	if controller.leaseMap == nil {
		return
	}
	if err := controller.leaseMap.Delete(identity); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		controller.warn("http_uprobe_stop_lease_delete_failed", "tgid", identity.TGID, "error", err)
	}
}

func (controller *httpUprobeStopController) warn(msg string, args ...any) {
	if controller.logger != nil {
		controller.logger.Warn(msg, args...)
	}
}

// recoverHTTPUprobeStopLeases runs before the mapping hook is attached. It
// resumes only the process generation recorded by BPF, then removes every
// lease. A pidfd is opened before checking procfs so the later signal cannot
// move to a recycled numeric PID.
func recoverHTTPUprobeStopLeases(leaseMap *ebpf.Map) error {
	if leaseMap == nil {
		return nil
	}
	iterator := leaseMap.Iterate()
	var identity httpUprobeProcessGeneration
	var stoppedAtNS uint64
	for iterator.Next(&identity, &stoppedAtNS) {
		pidfd, err := unix.PidfdOpen(int(identity.TGID), 0)
		if err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("open pidfd for HTTP uprobe stop lease %d: %w", identity.TGID, err)
		}
		if err == nil {
			matches, matchErr := processGenerationMatches(identity)
			if matchErr != nil && !processIsGone(matchErr) {
				_ = unix.Close(pidfd)
				return fmt.Errorf("verify HTTP uprobe stop lease for %d: %w", identity.TGID, matchErr)
			}
			if matches {
				err = unix.PidfdSendSignal(pidfd, unix.SIGCONT, nil, 0)
			}
			_ = unix.Close(pidfd)
			if err != nil && !errors.Is(err, unix.ESRCH) {
				return fmt.Errorf("resume HTTP uprobe stop lease for %d: %w", identity.TGID, err)
			}
		}
		if err := leaseMap.Delete(identity); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete HTTP uprobe stop lease for %d: %w", identity.TGID, err)
		}
	}
	if err := iterator.Err(); err != nil {
		return fmt.Errorf("iterate HTTP uprobe stop leases: %w", err)
	}
	return nil
}

// recoverAndUnpinHTTPUprobeStopLeases keeps --enable-uprobes=false safe after
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
