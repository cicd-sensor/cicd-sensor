//go:build linux && bpf_integration

package httpprepare

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A private PID namespace permits reuse without changing the node's PID allocator.
func TestProcessPIDReuse(t *testing.T) {
	if os.Getenv("CICD_PID_REUSE_CHILD") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestProcessPIDReuse$")
		cmd.Env = append(os.Environ(), "CICD_PID_REUSE_CHILD=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWPID | unix.CLONE_NEWNS}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("private PID namespace: %v\n%s", err, out)
		}
		return
	}
	if os.Getpid() != 1 {
		t.Fatal("refusing to change allocator outside private PID namespace")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		t.Fatal(err)
	}
	start := func() *exec.Cmd {
		cmd := exec.CommandContext(t.Context(), "/bin/sleep", "30")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	stop := func(cmd *exec.Cmd) { _ = cmd.Process.Kill(); _ = cmd.Wait() }
	victim := start()
	old, err := (Process{PID: victim.Process.Pid}).OpenProc()
	if err != nil {
		stop(victim)
		t.Fatal(err)
	}
	defer old.Close()
	pid := victim.Process.Pid
	stop(victim)
	// Go may allocate a thread while starting the next process. Retry in this
	// isolated namespace if such a thread consumed the requested number first.
	for range 20 {
		if err := os.WriteFile("/proc/sys/kernel/ns_last_pid", []byte(strconv.Itoa(pid-1)), 0o600); err != nil {
			t.Fatal(err)
		}
		replacement := start()
		if replacement.Process.Pid != pid {
			stop(replacement)
			continue
		}
		defer stop(replacement)
		fresh, err := (Process{PID: pid}).OpenProc()
		if err != nil {
			t.Fatal(err)
		}
		defer fresh.Close()
		stale, err := os.Open(fmt.Sprintf("/proc/self/fd/%d/root", old.Fd()))
		if err == nil {
			stale.Close()
			t.Fatal("old proc reference resolved to replacement")
		}
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ESRCH) {
			t.Fatal(err)
		}
		root, err := os.Open(fmt.Sprintf("/proc/self/fd/%d/root", fresh.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		root.Close()
		t.Logf("reused PID %d: old reference rejected, fresh reference opens replacement", pid)
		return
	}
	t.Fatal("could not force PID reuse")
}

func TestProcessDaemonNamespaceMismatch(t *testing.T) {
	// New PID namespace without a new proc mount deliberately reproduces an
	// inspect PID numbering scheme that does not match the daemon's /proc.
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("CICD_PID_NS_CHILD") == "1" {
		fmt.Println("ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}
	cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestProcessDaemonNamespaceMismatch$")
	cmd.Env = append(os.Environ(), "CICD_PID_NS_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWPID}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	var ready [6]byte
	if _, err := io.ReadFull(output, ready[:]); err != nil {
		t.Fatal(err)
	}
	proc, err := (Process{PID: 1, DaemonPID: cmd.Process.Pid}).OpenProc()
	if err == nil {
		proc.Close()
		t.Fatal("mismatched procfs accepted")
	}
	t.Logf("rejected mismatched daemon procfs: %v", err)
}

func TestPreparationRealUIDBoundary(t *testing.T) {
	if socket := os.Getenv("CICD_OTHER_UID_SOCKET"); socket != "" {
		// The parent explicitly varies filesystem permissions. In the second case
		// connect succeeds, so only the server's SO_PEERCRED check can reject us.
		client := NewRemote(socket)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://agent/prepare?pid=1&daemon_pid=0", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.client.Do(req)
		if os.Getenv("CICD_OTHER_UID_CONNECT") == "1" {
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != 403 {
				t.Fatalf("status=%d", response.StatusCode)
			}
		} else if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("expected filesystem denial: %v", err)
		}
		return
	}
	root, err := os.MkdirTemp("", "pid-uid-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	copyPath := filepath.Join(root, "test")
	dest, err := os.OpenFile(copyPath, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dest, source); err != nil {
		dest.Close()
		t.Fatal(err)
	}
	dest.Close()
	socket := servePreparationTest(t, func(context.Context, Process) error { t.Error("different UID reached worker"); return nil })
	if err := os.Chmod(filepath.Dir(socket), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		mode      os.FileMode
		connected string
	}{
		{name: "0600 socket denies connect", mode: 0o600},
		{name: "UID authentication rejects even if socket is writable", mode: 0o777, connected: "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Chmod(SocketPath(socket), tc.mode); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), copyPath, "-test.run=^TestPreparationRealUIDBoundary$")
			cmd.Env = append(os.Environ(), "CICD_OTHER_UID_SOCKET="+socket, "CICD_OTHER_UID_CONNECT="+tc.connected)
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("UID boundary: %v\n%s", err, out)
			}
		})
	}
}

func TestPreparationCredentialSyscallFailure(t *testing.T) {
	if os.Getenv("CICD_PEERCRED_FAILURE") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestPreparationCredentialSyscallFailure$")
		cmd.Env = append(os.Environ(), "CICD_PEERCRED_FAILURE=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("credential failure: %v\n%s", err, out)
		}
		return
	}
	// Fail only getsockopt(SO_PEERCRED), on every thread in this disposable child.
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_GETSOCKOPT, Jf: 3},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 32},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SO_PEERCRED, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	if errno != 0 {
		t.Fatal(errno)
	}
	socket := servePreparationTest(t, func(context.Context, Process) error { t.Error("unauthenticated caller reached worker"); return nil })
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://agent/prepare?pid=1&daemon_pid=0", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := NewRemote(socket).client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatalf("status=%d", response.StatusCode)
	}
}
