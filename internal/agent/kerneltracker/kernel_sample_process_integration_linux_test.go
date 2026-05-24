//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLinuxKernelSampleForkEndToEnd(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)

	cgroupID, err := lookupProcessCgroupID(int32(os.Getpid()), cgroupRoot)
	if err != nil {
		t.Fatalf("lookupProcessCgroupID: %v", err)
	}
	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, cgroupID); err != nil {
		t.Fatalf("PutCgroupIDInTrackedCgroupsMap parent cgroup: %v", err)
	}
	defer func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{cgroupID})
	}()

	command := exec.Command("/bin/sh", "-c", "true")
	if err := command.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	childPID := int32(command.Process.Pid)
	if err := command.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for fork event for pid %d", childPID)
		case message := <-kernelTracker.inputCh:
			sample, ok := message.(forkSample)
			if !ok {
				continue
			}
			if sample.Child.PID != childPID {
				continue
			}
			if sample.Child.StartBoottime == 0 {
				t.Fatal("fork event missing child start_boottime")
			}
			if sample.Parent.StartBoottime == 0 {
				t.Fatal("fork event missing parent start_boottime")
			}
			if sample.ChildCgroupID == 0 {
				t.Fatal("fork event missing cgroup id")
			}
			return
		}
	}
}

func TestLinuxKernelSampleExecFlow(t *testing.T) {
	truePath := requireBinary(t, "true")
	trueBytes, err := os.ReadFile(truePath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", truePath, err)
	}
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

	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, parentCgroupID); err != nil {
		t.Fatalf("PutCgroupIDInTrackedCgroupsMap parent cgroup: %v", err)
	}
	defer func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{parentCgroupID})
	}()

	runCase := func(t *testing.T, command *exec.Cmd) (execSample, emitEventRecord) {
		t.Helper()

		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("CombinedOutput: %v, output=%q", err, output)
		}
		childPID := int32(command.ProcessState.Pid())

		var forkInput forkSample
		waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "fork for exec flow", func(message engineInput) bool {
			sample, ok := message.(forkSample)
			if !ok || sample.Child.PID != childPID {
				return false
			}
			forkInput = sample
			return true
		})

		var execInput execSample
		waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "exec for exec flow", func(message engineInput) bool {
			sample, ok := message.(execSample)
			if !ok || sample.Identity.PID != childPID {
				return false
			}
			execInput = sample
			return true
		})

		jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
		state := destinationTrackedState(jobID, parentCgroupID)
		state.recordExec(jobID, forkInput.Parent, "/usr/bin/go-test-parent", nil, 0)

		forkEffects := handleEngineInput(state, forkInput)
		if len(forkEffects) != 0 {
			t.Fatalf("fork effects = %#v, want none", forkEffects)
		}

		effects := handleEngineInput(state, execInput)
		if len(effects) != 1 {
			t.Fatalf("exec effects len = %d, want 1", len(effects))
		}

		emit, ok := effects[0].(emitEventRecord)
		if !ok {
			t.Fatalf("effects[0] = %#v, want emitEventRecord", effects[0])
		}
		if emit.Record.EventType != jobevent.ProcessExec {
			t.Fatalf("event type = %q, want %q", emit.Record.EventType, jobevent.ProcessExec)
		}
		if emit.Record.Process.PID != execInput.Identity.PID {
			t.Fatalf("process pid = %d, want %d", emit.Record.Process.PID, execInput.Identity.PID)
		}
		wantAncestors := []jobevent.AncestorProcess{{ExecPath: "/usr/bin/go-test-parent"}}
		if got := emit.Record.Process.Ancestors; !reflect.DeepEqual(got, wantAncestors) {
			t.Fatalf("ancestors = %#v, want %#v", got, wantAncestors)
		}

		if !testProcessExists(state, jobID, execInput.Identity) {
			t.Fatal("exec node missing after exec flow")
		}
		summary := state.lookupProcessSummary(jobID, execInput.Identity)
		if summary.ExecPath == "" {
			t.Fatal("exec node missing exec path after exec flow")
		}
		if !reflect.DeepEqual(summary.Argv, emit.Record.Process.Argv) {
			t.Fatalf("summary argv = %#v, emitted argv = %#v", summary.Argv, emit.Record.Process.Argv)
		}
		return execInput, emit
	}

	tmpfsTruePath := func(t *testing.T) string {
		t.Helper()

		mountDir := filepath.Join(t.TempDir(), "tmpfs")
		if err := os.Mkdir(mountDir, 0o700); err != nil {
			t.Fatalf("Mkdir tmpfs mount point: %v", err)
		}
		if err := unix.Mount("tmpfs", mountDir, "tmpfs", 0, "mode=0700"); err != nil {
			t.Fatalf("Mount tmpfs for exec test: %v", err)
		}
		t.Cleanup(func() {
			if err := unix.Unmount(mountDir, 0); err != nil {
				t.Fatalf("Unmount tmpfs exec test mount: %v", err)
			}
		})

		tmpfsBinary := filepath.Join(mountDir, "true")
		if err := os.WriteFile(tmpfsBinary, trueBytes, 0o700); err != nil {
			t.Fatalf("Write tmpfs true binary: %v", err)
		}
		return tmpfsBinary
	}

	memfdTrueCommand := func(t *testing.T) *exec.Cmd {
		t.Helper()

		fd, err := unix.MemfdCreate("cicd-sensor-true", 0)
		if err != nil {
			t.Fatalf("MemfdCreate: %v", err)
		}
		memfd := os.NewFile(uintptr(fd), "memfd:cicd-sensor-true")
		if memfd == nil {
			_ = unix.Close(fd)
			t.Fatal("NewFile(memfd) returned nil")
		}
		t.Cleanup(func() {
			_ = memfd.Close()
		})

		if _, err := memfd.Write(trueBytes); err != nil {
			t.Fatalf("Write memfd true binary: %v", err)
		}
		if err := unix.Fchmod(fd, 0o700); err != nil {
			t.Fatalf("Fchmod memfd true binary: %v", err)
		}

		cmd := exec.Command("/proc/self/fd/3")
		cmd.ExtraFiles = []*os.File{memfd}
		return cmd
	}

	tests := []struct {
		name          string
		command       func(t *testing.T) *exec.Cmd
		wantArgv      []string
		wantTruncated bool
		wantMemfd     bool
	}{
		{
			name:     "middle empty",
			command:  commandForArgv([]string{truePath, "", "hello"}),
			wantArgv: []string{truePath, "", "hello"},
		},
		{
			name:     "trailing empty",
			command:  commandForArgv([]string{truePath, "hello", ""}),
			wantArgv: []string{truePath, "hello", ""},
		},
		{
			name:     "whitespace and trailing empty",
			command:  commandForArgv([]string{truePath, " ", "hello world", ""}),
			wantArgv: []string{truePath, " ", "hello world", ""},
		},
		{
			name:          "truncated large arg",
			command:       commandForArgv([]string{truePath, strings.Repeat("x", 4096)}),
			wantTruncated: true,
		},
		{
			name:      "memfd backed exec",
			command:   memfdTrueCommand,
			wantArgv:  []string{"/proc/self/fd/3"},
			wantMemfd: true,
		},
		{
			name: "tmpfs normal file exec",
			command: func(t *testing.T) *exec.Cmd {
				path := tmpfsTruePath(t)
				return exec.Command(path)
			},
			wantMemfd: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			execSample, emit := runCase(t, test.command(t))
			if execSample.ArgvTruncated != test.wantTruncated {
				t.Fatalf("argv truncated = %v, want %v", execSample.ArgvTruncated, test.wantTruncated)
			}
			if execSample.IsMemfd != test.wantMemfd {
				t.Fatalf("is_memfd = %v, want %v", execSample.IsMemfd, test.wantMemfd)
			}
			if got, _ := emit.Record.Payload["is_memfd"].(bool); got != test.wantMemfd {
				t.Fatalf("payload[is_memfd] = %v, want %v", got, test.wantMemfd)
			}

			wantArgv := test.wantArgv
			if wantArgv == nil {
				wantArgv = splitArgv(execSample.ArgvBlob, int(execSample.Argc))
			}
			if got := emit.Record.Process.Argv; !reflect.DeepEqual(got, wantArgv) {
				t.Fatalf("exec argv = %#v, want %#v", got, wantArgv)
			}

			if test.wantTruncated {
				if got := emit.Record.Tags["truncated"]; got != "argv" {
					t.Fatalf("truncated tag = %q, want argv", got)
				}
				return
			}
			if got, ok := emit.Record.Tags["truncated"]; ok {
				t.Fatalf("unexpected truncated tag = %q", got)
			}
		})
	}
}

func commandForArgv(argv []string) func(t *testing.T) *exec.Cmd {
	return func(t *testing.T) *exec.Cmd {
		t.Helper()
		if len(argv) == 0 {
			t.Fatal("argv must include argv[0]")
		}
		return exec.Command(argv[0], argv[1:]...)
	}
}
