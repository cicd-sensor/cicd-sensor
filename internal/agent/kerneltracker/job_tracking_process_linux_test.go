//go:build linux

package kerneltracker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackfillProcessNode_Self(t *testing.T) {
	identity := processIdentity{PID: int32(os.Getpid()), StartBoottime: 12345}

	node := backfillProcessNode(identity)
	if node == nil {
		t.Fatal("backfillProcessNode(self) returned nil")
	}

	if node.Identity != identity {
		t.Errorf("identity mutated: got %+v want %+v", node.Identity, identity)
	}
	if node.State != processStateRunning {
		t.Errorf("state: got %v want processStateRunning", node.State)
	}

	wantExe, err := filepath.EvalSymlinks("/proc/self/exe")
	if err != nil {
		t.Fatalf("EvalSymlinks(/proc/self/exe): %v", err)
	}
	if node.ExecPath != wantExe {
		t.Errorf("ExecPath: got %q want %q", node.ExecPath, wantExe)
	}

	if len(node.Argv) == 0 {
		t.Error("Argv: empty; want at least os.Args[0]")
	}
	if len(node.Argv) > 0 && node.Argv[0] != os.Args[0] {
		t.Errorf("Argv[0]: got %q want %q", node.Argv[0], os.Args[0])
	}
}

func TestBackfillProcessNode_NonexistentPID(t *testing.T) {
	// pid 0 is the swapper/idle task and has no /proc/0/exe entry; any
	// readlink returns ENOENT.
	identity := processIdentity{PID: 0, StartBoottime: 1}
	if node := backfillProcessNode(identity); node != nil {
		t.Errorf("expected nil for pid 0, got %+v", node)
	}
}

func TestSplitCmdline(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want []string
	}{
		{"empty", nil, nil},
		{"only nuls", []byte{0, 0, 0}, nil},
		{"single arg with trailing nul", []byte("ls\x00"), []string{"ls"}},
		{"multi arg", []byte("ls\x00-la\x00/tmp\x00"), []string{"ls", "-la", "/tmp"}},
		{"no trailing nul", []byte("ls\x00-la"), []string{"ls", "-la"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitCmdline(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("len: got %d (%q) want %d (%q)", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("argv[%d]: got %q want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
