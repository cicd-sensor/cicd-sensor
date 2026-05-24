package kerneltracker

import (
	"context"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

func TestHandlePurgeTick(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "purge deletes exited node past grace period",
			run: func(t *testing.T) {
				jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
				identity := processIdentity{PID: 101, StartBoottime: 2}

				state := newTrackedState(jobID, 42)
				state.recordExec(jobID, identity, "", nil, 0)

				handleEngineInput(state, exitSample{Identity: identity, CgroupID: 42})
				time.Sleep(processExitGracePeriod + time.Second)

				effects := handleEngineInput(state, commandPurgeExitedProcesses{})
				if len(effects) != 0 {
					t.Fatalf("purge tick emitted effects: %#v", effects)
				}

				if testProcessExists(state, jobID, identity) {
					t.Fatal("exited node still present after grace period")
				}
				if got := testExitedProcessCount(state, jobID); got != 0 {
					t.Fatalf("exited process count = %d, want 0", got)
				}
			},
		},
		{
			name: "purge retains exited node within grace period",
			run: func(t *testing.T) {
				jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
				identity := processIdentity{PID: 101, StartBoottime: 2}

				state := newTrackedState(jobID, 42)
				state.recordExec(jobID, identity, "", nil, 0)

				handleEngineInput(state, exitSample{Identity: identity, CgroupID: 42})
				time.Sleep(processExitGracePeriod - time.Second)

				handleEngineInput(state, commandPurgeExitedProcesses{})

				if !testProcessExists(state, jobID, identity) {
					t.Fatal("exited node removed before grace period elapsed")
				}
				if got := testExitedProcessCount(state, jobID); got != 1 {
					t.Fatalf("exited process count = %d, want 1", got)
				}
			},
		},
		{
			name: "duplicate exit is queued once",
			run: func(t *testing.T) {
				jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
				identity := processIdentity{PID: 101, StartBoottime: 2}

				state := newTrackedState(jobID, 42)
				state.recordExec(jobID, identity, "", nil, 0)

				handleEngineInput(state, exitSample{Identity: identity, CgroupID: 42})
				handleEngineInput(state, exitSample{Identity: identity, CgroupID: 42})

				if got := testExitedProcessCount(state, jobID); got != 1 {
					t.Fatalf("exited process count = %d, want 1", got)
				}
			},
		},
		{
			name: "purge processes fifo head then stops at first unexpired",
			run: func(t *testing.T) {
				jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
				first := processIdentity{PID: 101, StartBoottime: 2}
				second := processIdentity{PID: 102, StartBoottime: 3}

				state := newTrackedState(jobID, 42)
				state.recordExec(jobID, first, "", nil, 0)
				state.recordExec(jobID, second, "", nil, 0)

				handleEngineInput(state, exitSample{Identity: first, CgroupID: 42})
				time.Sleep(2 * time.Second)
				handleEngineInput(state, exitSample{Identity: second, CgroupID: 42})
				time.Sleep(processExitGracePeriod - time.Second)

				handleEngineInput(state, commandPurgeExitedProcesses{})

				if testProcessExists(state, jobID, first) {
					t.Fatal("oldest exited node still present after purge")
				}
				if !testProcessExists(state, jobID, second) {
					t.Fatal("newer exited node was removed before grace period elapsed")
				}
				if got := testExitedProcessCount(state, jobID); got != 1 {
					t.Fatalf("exited process count = %d, want 1", got)
				}
			},
		},
		{
			name: "purge does not touch live nodes",
			run: func(t *testing.T) {
				jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
				identity := processIdentity{PID: 101, StartBoottime: 2}

				state := newTrackedState(jobID, 42)
				state.recordExec(jobID, identity, "/usr/bin/bash", nil, 0)

				handleEngineInput(state, execSample{
					Identity: identity,
					CgroupID: 42,
					TsNs:     10,
					ExecPath: "/usr/bin/bash",
					ArgvBlob: []byte{'b', 'a', 's', 'h', 0},
					Argc:     1,
				})
				time.Sleep(processExitGracePeriod + time.Second)

				handleEngineInput(state, commandPurgeExitedProcesses{})

				if !testProcessExists(state, jobID, identity) {
					t.Fatal("live node was removed by purge tick")
				}
				if got := testExitedProcessCount(state, jobID); got != 0 {
					t.Fatalf("exited process count = %d, want 0", got)
				}
			},
		},
		{
			name: "purge handles multiple job contexts independently",
			run: func(t *testing.T) {
				jobOne := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
				jobTwo := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "456")
				first := processIdentity{PID: 101, StartBoottime: 2}
				second := processIdentity{PID: 201, StartBoottime: 3}

				state := newTrackedState(jobOne, 42)
				state.registerJob(jobTwo, defaultEventRecordBufferSize)
				state.bind(jobTwo, 84)
				state.recordExec(jobOne, first, "", nil, 0)
				state.recordExec(jobTwo, second, "", nil, 0)

				handleEngineInput(state, exitSample{Identity: first, CgroupID: 42})
				time.Sleep(2 * time.Second)
				handleEngineInput(state, exitSample{Identity: second, CgroupID: 84})
				time.Sleep(processExitGracePeriod - time.Second)

				handleEngineInput(state, commandPurgeExitedProcesses{})

				if testProcessExists(state, jobOne, first) {
					t.Fatal("expired node in first job context was not purged")
				}
				if !testProcessExists(state, jobTwo, second) {
					t.Fatal("unexpired node in second job context was purged")
				}
				if got := testExitedProcessCount(state, jobOne); got != 0 {
					t.Fatalf("job one exited process count = %d, want 0", got)
				}
				if got := testExitedProcessCount(state, jobTwo); got != 1 {
					t.Fatalf("job two exited process count = %d, want 1", got)
				}
			},
		},
		{
			name: "purge is no-op when queue is empty",
			run: func(t *testing.T) {
				jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")

				state := newTrackedState(jobID, 42)
				beforeNodes := testProcessNodeCount(state, jobID)

				effects := handleEngineInput(state, commandPurgeExitedProcesses{})
				if len(effects) != 0 {
					t.Fatalf("purge tick emitted effects: %#v", effects)
				}

				if got := testProcessNodeCount(state, jobID); got != beforeNodes {
					t.Fatalf("node count = %d, want %d", got, beforeNodes)
				}
				if got := testExitedProcessCount(state, jobID); got != 0 {
					t.Fatalf("exited process count = %d, want 0", got)
				}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				test.run(t)
			})
		})
	}
}

func TestSplitArgv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		blob []byte
		argc int
		want []string
	}{
		{
			name: "zero argc with nil blob",
		},
		{
			name: "zero argc with non-empty blob",
			blob: []byte("ignored\x00"),
		},
		{
			name: "two normal args",
			blob: []byte("a\x00b\x00"),
			argc: 2,
			want: []string{"a", "b"},
		},
		{
			name: "middle empty arg",
			blob: []byte("/bin/echo\x00\x00hello\x00"),
			argc: 3,
			want: []string{"/bin/echo", "", "hello"},
		},
		{
			name: "trailing empty arg",
			blob: []byte("/bin/echo\x00hello\x00\x00"),
			argc: 3,
			want: []string{"/bin/echo", "hello", ""},
		},
		{
			name: "leading empty arg",
			blob: []byte("\x00hello\x00"),
			argc: 2,
			want: []string{"", "hello"},
		},
		{
			name: "consecutive empty args",
			blob: []byte("cmd\x00\x00\x00tail\x00"),
			argc: 4,
			want: []string{"cmd", "", "", "tail"},
		},
		{
			name: "whitespace only arg",
			blob: []byte("cmd\x00 \x00"),
			argc: 2,
			want: []string{"cmd", " "},
		},
		{
			name: "arg containing spaces",
			blob: []byte("cmd\x00hello world\x00"),
			argc: 2,
			want: []string{"cmd", "hello world"},
		},
		{
			name: "argc caps decoded args",
			blob: []byte("a\x00b\x00c\x00"),
			argc: 2,
			want: []string{"a", "b"},
		},
		{
			name: "argc larger than blob args stops at blob end",
			blob: []byte("a\x00b\x00"),
			argc: 4,
			want: []string{"a", "b"},
		},
		{
			name: "missing final nul keeps partial arg",
			blob: []byte("a\x00partial"),
			argc: 2,
			want: []string{"a", "partial"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := splitArgv(test.blob, test.argc)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("splitArgv() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestKernelTrackerRun_PurgeTickerExitsOnContextCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		engine := newTestKernelTracker(nil, nil, noopKernelIO{}, "")

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- engine.Run(ctx)
		}()

		go func() {
			// Let the ticker fire a few times so cancel happens while the loop is
			// actively consuming periodic purge ticks.
			time.Sleep(3 * processPurgeInterval)
			cancel()
		}()

		if err := <-done; err != nil {
			t.Fatalf("Run error = %v, want nil", err)
		}

		synctest.Wait()
	})
}

func TestKernelTrackerRun_PurgeTickerPurgesExpiredNodes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
		identity := processIdentity{PID: 101, StartBoottime: 2}

		engine := newTestKernelTracker(nil, nil, noopKernelIO{}, "")
		engine.jobTracking = newTrackedState(jobID, 42)
		engine.jobTracking.recordExec(jobID, identity, "", nil, 0)
		handleEngineInput(engine.jobTracking, exitSample{Identity: identity, CgroupID: 42})

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- engine.Run(ctx)
		}()

		go func() {
			time.Sleep(processExitGracePeriod + 2*processPurgeInterval)
			cancel()
		}()

		if err := <-done; err != nil {
			t.Fatalf("Run error = %v, want nil", err)
		}

		if testProcessExists(engine.jobTracking, jobID, identity) {
			t.Fatal("expired exited node was not purged through the Run -> inputCh -> handleEngineInput path")
		}
		if got := testExitedProcessCount(engine.jobTracking, jobID); got != 0 {
			t.Fatalf("exited process count = %d, want 0", got)
		}

		synctest.Wait()
	})
}

func TestTransitionProcessSubsystem_Fork(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	grandparentIdentity := processIdentity{PID: 99, StartBoottime: 1}
	parentIdentity := processIdentity{PID: 100, StartBoottime: 1}
	childIdentity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, grandparentIdentity, "/sbin/systemd", nil, 0)
	state.recordFork(jobID, parentIdentity, grandparentIdentity)
	state.recordExec(jobID, parentIdentity, "/usr/bin/bash", []byte{'b', 'a', 's', 'h', 0}, 1)

	effects := handleEngineInput(state, forkSample{
		Child:         childIdentity,
		Parent:        parentIdentity,
		ChildCgroupID: 42,
	})

	if len(effects) != 0 {
		t.Fatalf("fork emitted effects: %#v", effects)
	}

	if !testProcessExists(state, jobID, childIdentity) {
		t.Fatal("child process node missing after fork")
	}
	summary := state.lookupProcessSummary(jobID, childIdentity)
	if summary.StartBoottime != childIdentity.StartBoottime {
		t.Fatalf("child start_boottime = %d, want %d", summary.StartBoottime, childIdentity.StartBoottime)
	}
	if summary.ExecPath != "/usr/bin/bash" {
		t.Fatalf("child exec path after fork = %q, want inherited parent path", summary.ExecPath)
	}
	if got := summary.Argv; !reflect.DeepEqual(got, []string{"bash"}) {
		t.Fatalf("child argv after fork = %#v, want inherited parent argv", got)
	}
	// newest-first ordering: [0] is the immediate parent (bash), [1] is its
	// parent (systemd, copied from the source node's chain).
	want := []jobevent.AncestorProcess{
		{ExecPath: "/usr/bin/bash", Argv: []string{"bash"}},
		{ExecPath: "/sbin/systemd"},
	}
	if got := summary.Ancestors; !reflect.DeepEqual(got, want) {
		t.Fatalf("ancestors = %#v, want %#v", got, want)
	}
}

func TestTransitionProcessSubsystem_ForkNoopBranches(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	parentIdentity := processIdentity{PID: 100, StartBoottime: 1}
	childIdentity := processIdentity{PID: 101, StartBoottime: 2}

	t.Run("untracked cgroup", func(t *testing.T) {
		t.Parallel()

		state := newJobTrackingState()
		effects := handleEngineInput(state, forkSample{
			Child:         childIdentity,
			Parent:        parentIdentity,
			ChildCgroupID: 42,
		})

		if len(effects) != 0 {
			t.Fatalf("untracked fork emitted effects: %#v", effects)
		}
		if testProcessExists(state, jobID, childIdentity) {
			t.Fatal("untracked fork unexpectedly created process state")
		}
	})

	t.Run("tracked cgroup without process state", func(t *testing.T) {
		t.Parallel()

		state := newJobTrackingState()
		state.jobs[jobID] = struct{}{}
		state.bind(jobID, 42)

		effects := handleEngineInput(state, forkSample{
			Child:         childIdentity,
			Parent:        parentIdentity,
			ChildCgroupID: 42,
		})

		if len(effects) != 0 {
			t.Fatalf("fork without process state emitted effects: %#v", effects)
		}
		if testProcessExists(state, jobID, childIdentity) {
			t.Fatal("fork without process state unexpectedly created process node")
		}
	})
}

func TestTransitionProcessSubsystem_Fork_TruncatesAncestorDepthAtCap(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	parentIdentity := processIdentity{PID: 100, StartBoottime: 1}
	childIdentity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	previous := processIdentity{PID: 1, StartBoottime: 1}
	state.recordExec(jobID, previous, "/path/ancestor", nil, 0)
	for index := 0; index < maxAncestorDepth; index++ {
		current := processIdentity{PID: int32(index + 2), StartBoottime: uint64(index + 2)}
		state.recordFork(jobID, current, previous)
		state.recordExec(jobID, current, "/path/ancestor", nil, 0)
		previous = current
	}
	state.recordFork(jobID, parentIdentity, previous)
	state.recordExec(jobID, parentIdentity, "/usr/bin/bash", nil, 0)

	handleEngineInput(state, forkSample{
		Child:         childIdentity,
		Parent:        parentIdentity,
		ChildCgroupID: 42,
	})

	if !testProcessExists(state, jobID, childIdentity) {
		t.Fatal("child process node missing after fork")
	}
	summary := state.lookupProcessSummary(jobID, childIdentity)
	if len(summary.Ancestors) != maxAncestorDepth {
		t.Fatalf("ancestor count = %d, want %d", len(summary.Ancestors), maxAncestorDepth)
	}
	// newest-first ordering with depth cap: [0] is the new parent, the
	// oldest entry in the parent's chain is dropped from the tail.
	if got := summary.Ancestors[0].ExecPath; got != "/usr/bin/bash" {
		t.Fatalf("ancestor[0].exec_path = %q, want %q", got, "/usr/bin/bash")
	}
	if got := summary.Ancestors[maxAncestorDepth-1].ExecPath; got != "/path/ancestor" {
		t.Fatalf("last ancestor.exec_path = %q, want %q", got, "/path/ancestor")
	}
}

func TestTransitionProcessSubsystem_Exec_EmitsEventRecord(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	systemd := processIdentity{PID: 1, StartBoottime: 1}
	bash := processIdentity{PID: 100, StartBoottime: 1}
	state.recordExec(jobID, systemd, "/sbin/systemd", nil, 0)
	state.recordFork(jobID, bash, systemd)
	state.recordExec(jobID, bash, "/usr/bin/bash", nil, 0)
	state.recordFork(jobID, identity, bash)

	effects := handleEngineInput(state, execSample{
		Identity:      identity,
		CgroupID:      42,
		TsNs:          10,
		ExecPath:      "/usr/bin/echo",
		Argc:          2,
		ArgvBlob:      []byte{'e', 'c', 'h', 'o', 0, 'p', 'a', 'r', 't', 'i', 'a', 'l'},
		ArgvTruncated: true,
		ArgvFaulted:   true,
		IsMemfd:       true,
	})

	if !testProcessExists(state, jobID, identity) {
		t.Fatal("process node missing after exec")
	}
	summary := state.lookupProcessSummary(jobID, identity)
	if summary.ExecPath != "/usr/bin/echo" {
		t.Fatalf("exec path = %q, want %q", summary.ExecPath, "/usr/bin/echo")
	}
	if got, want := summary.Argv, []string{"echo", "partial"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %#v, want %#v", got, want)
	}

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	if emit.JobID != jobID {
		t.Fatalf("emit job id = %q, want %q", emit.JobID, jobID)
	}
	if emit.Record.EventType != jobevent.ProcessExec {
		t.Fatalf("event type = %q, want %q", emit.Record.EventType, jobevent.ProcessExec)
	}
	if emit.Record.Process.PID != identity.PID {
		t.Fatalf("process pid = %d, want %d", emit.Record.Process.PID, identity.PID)
	}
	if emit.Record.Process.StartBoottime != identity.StartBoottime {
		t.Fatalf("process start_boottime = %d, want %d", emit.Record.Process.StartBoottime, identity.StartBoottime)
	}
	want := []jobevent.AncestorProcess{
		{ExecPath: "/usr/bin/bash"},
		{ExecPath: "/sbin/systemd"},
	}
	if got := emit.Record.Process.Ancestors; !reflect.DeepEqual(got, want) {
		t.Fatalf("ancestors = %#v, want %#v", got, want)
	}
	if got := emit.Record.Tags["truncated"]; got != "argv" {
		t.Fatalf("truncated tag = %q, want %q", got, "argv")
	}
	if got := emit.Record.Tags["faulted"]; got != "argv" {
		t.Fatalf("faulted tag = %q, want %q", got, "argv")
	}
	if got, _ := emit.Record.Payload["is_memfd"].(bool); !got {
		t.Fatalf("payload[is_memfd] = %v, want true", got)
	}
}

func TestLookupProcessSummaryFallbackIncludesIdentity(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 202}
	state := newJobTrackingState()

	summary := state.lookupProcessSummary(jobID, identity)
	if summary.PID != identity.PID {
		t.Fatalf("pid = %d, want %d", summary.PID, identity.PID)
	}
	if summary.StartBoottime != identity.StartBoottime {
		t.Fatalf("start_boottime = %d, want %d", summary.StartBoottime, identity.StartBoottime)
	}
}

func TestTransitionProcessSubsystem_Exec_ArgvShapeAndTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		argvBlob     []byte
		argc         uint32
		truncated    bool
		faulted      bool
		wantArgv     []string
		wantTags     map[string]string
		wantNoTagKey []string
	}{
		{
			name:         "empty and whitespace args are preserved without tags",
			argvBlob:     []byte("cmd\x00\x00 \x00hello world\x00"),
			argc:         4,
			wantArgv:     []string{"cmd", "", " ", "hello world"},
			wantNoTagKey: []string{"truncated", "faulted"},
		},
		{
			name:      "truncated only keeps partial final arg",
			argvBlob:  []byte("cmd\x00partial"),
			argc:      2,
			truncated: true,
			wantArgv:  []string{"cmd", "partial"},
			wantTags:  map[string]string{"truncated": "argv"},
		},
		{
			name:     "faulted only",
			argvBlob: []byte("cmd\x00arg\x00"),
			argc:     2,
			faulted:  true,
			wantArgv: []string{"cmd", "arg"},
			wantTags: map[string]string{"faulted": "argv"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
			identity := processIdentity{PID: 101, StartBoottime: 2}
			state := destinationTrackedState(jobID, 42)

			effects := handleEngineInput(state, execSample{
				Identity:      identity,
				CgroupID:      42,
				TsNs:          10,
				ExecPath:      "/usr/bin/test",
				Argc:          test.argc,
				ArgvBlob:      test.argvBlob,
				ArgvTruncated: test.truncated,
				ArgvFaulted:   test.faulted,
			})

			emit, ok := singleEmitEventRecordEffect(effects)
			if !ok {
				t.Fatalf("effects = %#v, want single emitEventRecord", effects)
			}
			if got := emit.Record.Process.Argv; !reflect.DeepEqual(got, test.wantArgv) {
				t.Fatalf("argv = %#v, want %#v", got, test.wantArgv)
			}
			for key, want := range test.wantTags {
				if got := emit.Record.Tags[key]; got != want {
					t.Fatalf("tag %q = %q, want %q", key, got, want)
				}
			}
			for _, key := range test.wantNoTagKey {
				if got, ok := emit.Record.Tags[key]; ok {
					t.Fatalf("unexpected tag %q = %q", key, got)
				}
			}
		})
	}
}

func TestTransitionProcessSubsystem_ExitLogicalDelete(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "", nil, 0)

	effects := handleEngineInput(state, exitSample{
		Identity: identity,
		CgroupID: 42,
	})

	if len(effects) != 0 {
		t.Fatalf("exit emitted effects: %#v", effects)
	}

	if !testProcessExists(state, jobID, identity) {
		t.Fatal("process node missing after exit")
	}
	if !testProcessIsExited(state, jobID, identity) {
		t.Fatal("process was not retained as exited")
	}
	if got := testExitedProcessCount(state, jobID); got != 1 {
		t.Fatalf("exited process count = %d, want 1", got)
	}
}

func TestRemoveJob_DropsProcessContext(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := destinationTrackedState(jobID, 42)
	identity := processIdentity{PID: 1, StartBoottime: 2}
	state.recordExec(jobID, identity, "", nil, 0)

	effects := handleEngineInput(state, commandRemoveJob{JobID: jobID})
	runTestEffects(t, state, effects)
	if testProcessExists(state, jobID, identity) {
		t.Fatalf("process context for %q still present after remove", jobID)
	}
}
