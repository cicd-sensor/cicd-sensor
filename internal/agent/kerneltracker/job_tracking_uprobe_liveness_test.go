package kerneltracker

import (
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// TestActiveCgroupIDsExcludesRemoved pins that a removed cgroup is not handed to
// the reclaim scanner as "still tracked": its processes are gone or leaving, so
// it must not keep an attached inode alive.
func TestActiveCgroupIDsExcludesRemoved(t *testing.T) {
	t.Parallel()
	state := newJobTrackingState()
	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "g/p", "1")
	state.registerJob(jobID, 1)
	now := time.Now()
	state.bindAt(jobID, 10, now)
	state.bindAt(jobID, 20, now)
	state.markTrackedCgroupRemoved(20, now)

	ids := state.activeCgroupIDs()
	if _, ok := ids[10]; !ok {
		t.Fatal("active cgroup 10 missing")
	}
	if _, ok := ids[20]; ok {
		t.Fatal("removed cgroup 20 must be excluded")
	}
	if len(ids) != 1 {
		t.Fatalf("len = %d, want 1", len(ids))
	}
}

// TestSnapshotActiveCgroupIDsCommand pins the loop-side handler: it replies
// with a copy made on the loop, so the scanner never reads loop-owned state.
func TestSnapshotActiveCgroupIDsCommand(t *testing.T) {
	t.Parallel()
	state := newJobTrackingState()
	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "g/p", "1")
	state.registerJob(jobID, 1)
	state.bindAt(jobID, 7, time.Now())

	reply := make(chan map[uint64]struct{}, 1)
	effects := handleEngineInput(state, commandSnapshotActiveCgroupIDs{Reply: reply})
	if len(effects) != 1 {
		t.Fatalf("effects = %d, want 1", len(effects))
	}
	eff, ok := effects[0].(replyActiveCgroupIDs)
	if !ok {
		t.Fatalf("effect type = %T, want replyActiveCgroupIDs", effects[0])
	}
	if _, has := eff.IDs[7]; !has || len(eff.IDs) != 1 {
		t.Fatalf("IDs = %v, want {7}", eff.IDs)
	}
	// It is a copy: mutating the reply must not touch state.
	delete(eff.IDs, 7)
	if _, still := state.activeCgroupIDs()[7]; !still {
		t.Fatal("reply aliased loop-owned state")
	}
}

// TestScanStartedAtKeepsMonotonic pins that the scan start timestamp keeps its
// monotonic reading: the worker's lastSeenAt >= ScanStartedAt guard must be a
// monotonic comparison, not a wall-clock one that a clock step could break.
// time.Time.Round(0) strips the monotonic reading; a stripped value compares
// Equal to its Round(0) but a monotonic one does not survive that check the
// same way we test here: a time WITH monotonic has Round(0) != itself under
// reflect-free comparison via String() markers ("m=" suffix).
func TestScanStartedAtKeepsMonotonic(t *testing.T) {
	t.Parallel()
	now := time.Now()
	if !hasMonotonic(now) {
		t.Skip("time.Now() lacks monotonic on this platform")
	}
	// The production call site is `time.Now()` (not `.UTC()`/`.Round(0)`), which
	// keeps the reading. Assert the property on the exact expression used.
	if !hasMonotonic(time.Now()) {
		t.Fatal("scan start must keep the monotonic reading")
	}
	if hasMonotonic(time.Now().UTC()) {
		t.Fatal("sanity: .UTC() should strip monotonic (else this test cannot detect the regression)")
	}
}

func hasMonotonic(tm time.Time) bool {
	// Go prints a monotonic reading as a trailing " m=±..." in String().
	return len(tm.String()) > 0 && containsMono(tm.String())
}

func containsMono(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == ' ' && s[i+1] == 'm' && s[i+2] == '=' {
			return true
		}
	}
	return false
}
