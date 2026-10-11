//go:build linux

package kernelio

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/ebpf/link"
)

type testTracking struct {
	members map[uint64]uint64
	err     error
}

func (s testTracking) httpRootCgroup(id uint64) uint64 { return s.members[id] }
func (s testTracking) httpRootActive(id uint64) (bool, error) {
	return id != 0 && s.members[id] == id, s.err
}

func TestHTTPUprobeReclaim(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name              string
		members           map[uint64]uint64
		scanErr           error
		pending, canceled bool
		remain            int
	}{
		{name: "active root retains unused preparation", members: map[uint64]uint64{7: 7}, remain: 1},
		{name: "child cannot retain links after root deletion", members: map[uint64]uint64{2: 7}},
		{name: "removed child does not end its parent", members: map[uint64]uint64{7: 7, 2: 0}, remain: 1},
		{name: "root ending closes target"},
		{name: "zero root is removed", members: map[uint64]uint64{7: 0}},
		{name: "different root cannot retain old link", members: map[uint64]uint64{1: 8, 8: 8}},
		{name: "unreadable root keeps links", scanErr: errors.New("changing"), remain: 1},
		{name: "pending preparation yields", pending: true, remain: 1},
		{name: "cancellation leaves shutdown responsible", canceled: true, remain: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newHTTPUprobeWorker(nil, nil, "", nil, nil)
			w.tracking = testTracking{members: tc.members, err: tc.scanErr}
			closed := 0
			key := httpTargetKey{rootCgroupID: 7, file: mappedFileIdentity{inode: 42}}
			w.attachedTargets[key] = &attachedUprobeTarget{links: []link.Link{notifyCloseLink{notify: func() { closed++ }}}}
			if tc.pending {
				w.preparationRequests <- &httpPreparationRequest{}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			w.reconcileTargets(ctx)
			if len(w.attachedTargets) != tc.remain || closed != 1-tc.remain {
				t.Fatalf("remaining=%d closed=%d", len(w.attachedTargets), closed)
			}
		})
	}
}

func TestHTTPUprobeRootsHaveIndependentLinks(t *testing.T) {
	w := newHTTPUprobeWorker(nil, nil, "", nil, nil)
	w.tracking = testTracking{members: map[uint64]uint64{8: 8, 2: 8}}
	closed := map[uint64]int{}
	for _, rootCgroupID := range []uint64{7, 8} {
		w.attachedTargets[httpTargetKey{rootCgroupID: rootCgroupID, file: mappedFileIdentity{inode: 42}}] = &attachedUprobeTarget{links: []link.Link{notifyCloseLink{notify: func() { closed[rootCgroupID]++ }}}}
	}
	w.reconcileTargets(t.Context())
	if closed[7] != 1 || closed[8] != 0 || len(w.attachedTargets) != 1 {
		t.Fatalf("close counts=%v targets=%d", closed, len(w.attachedTargets))
	}
	w.closeAll()
	if closed[8] != 1 {
		t.Fatal("shutdown did not close remaining root")
	}
}

func TestPreparationRejectsEndedRoot(t *testing.T) {
	w := newHTTPUprobeWorker(nil, nil, "", nil, nil)
	w.tracking = testTracking{members: map[uint64]uint64{1: 8, 8: 8}}
	for _, tc := range []struct {
		name         string
		rootCgroupID uint64
	}{
		{name: "zero root rejected"},
		{name: "different root rejected", rootCgroupID: 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := w.prepareFile(t.Context(), nil, nil, 1, tc.rootCgroupID); !errors.Is(err, errHTTPTrackingEnded) {
				t.Fatalf("late preparation: %v", err)
			}
		})
	}
}
