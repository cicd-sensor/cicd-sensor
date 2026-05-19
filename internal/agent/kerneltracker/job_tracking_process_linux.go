//go:build linux

package kerneltracker

import (
	"bytes"
	"os"
	"strconv"
)

// backfillProcessNode synthesizes a processNode from /proc for an identity
// whose fork/exec was never observed (pre-existing process at agent attach,
// or events lost before tracking started). Returns nil if /proc/<pid> is
// unreadable; the caller falls back to a PID-only ProcessSummary.
//
// Identity is taken verbatim from the BPF event. /proc cannot expose
// start_boottime at ns precision, so verification against identity is not
// possible; PID-reuse misattribution is bounded by the μs gap between event
// and lookup.
func backfillProcessNode(identity processIdentity) *processNode {
	pidStr := strconv.Itoa(int(identity.PID))

	exe, err := os.Readlink("/proc/" + pidStr + "/exe")
	if err != nil {
		return nil
	}

	var argv []string
	if cmdline, err := os.ReadFile("/proc/" + pidStr + "/cmdline"); err == nil {
		argv = splitCmdline(cmdline)
	}

	return &processNode{
		Identity: identity,
		State:    processStateRunning,
		ExecPath: exe,
		Argv:     argv,
	}
}

// splitCmdline splits /proc/<pid>/cmdline into argv. The blob is
// NUL-separated and typically NUL-terminated; trim trailing NULs first so
// strings.Split doesn't emit a spurious empty final element.
func splitCmdline(blob []byte) []string {
	blob = bytes.TrimRight(blob, "\x00")
	if len(blob) == 0 {
		return nil
	}
	parts := bytes.Split(blob, []byte{0})
	argv := make([]string, len(parts))
	for i, p := range parts {
		argv[i] = string(p)
	}
	return argv
}
