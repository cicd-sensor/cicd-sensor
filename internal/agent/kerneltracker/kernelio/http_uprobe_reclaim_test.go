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

func (s testTracking) httpOwner(id uint64) uint64 { return s.members[id] }
func (s testTracking) httpOwners() (map[uint64]struct{}, error) {
	owners := make(map[uint64]struct{})
	for _, owner := range s.members {
		if owner != 0 {
			owners[owner] = struct{}{}
		}
	}
	return owners, s.err
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
		{name: "active owner retains unused preparation", members: map[uint64]uint64{1: 7}, remain: 1},
		{name: "child retains owner after root deletion", members: map[uint64]uint64{2: 7}, remain: 1},
		{name: "removed child does not end its parent", members: map[uint64]uint64{1: 7, 2: 0}, remain: 1},
		{name: "last member ending closes target"},
		{name: "zero owner is removed", members: map[uint64]uint64{1: 0}},
		{name: "new owner at reused cgroup does not retain old link", members: map[uint64]uint64{1: 8}},
		{name: "changing snapshot keeps links", scanErr: errors.New("changing"), remain: 1},
		{name: "pending preparation yields", pending: true, remain: 1},
		{name: "cancellation leaves shutdown responsible", canceled: true, remain: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newHTTPUprobeWorker(nil, nil, "", nil, nil)
			w.tracking = testTracking{members: tc.members, err: tc.scanErr}
			closed := 0
			key := httpTargetKey{owner: 7, file: mappedFileIdentity{inode: 42}}
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

func TestHTTPUprobeOwnersHaveIndependentLinks(t *testing.T) {
	w := newHTTPUprobeWorker(nil, nil, "", nil, nil)
	w.tracking = testTracking{members: map[uint64]uint64{2: 8}}
	closed := map[uint64]int{}
	for _, owner := range []uint64{7, 8} {
		w.attachedTargets[httpTargetKey{owner: owner, file: mappedFileIdentity{inode: 42}}] = &attachedUprobeTarget{links: []link.Link{notifyCloseLink{notify: func() { closed[owner]++ }}}}
	}
	w.reconcileTargets(t.Context())
	if closed[7] != 1 || closed[8] != 0 || len(w.attachedTargets) != 1 {
		t.Fatalf("close counts=%v targets=%d", closed, len(w.attachedTargets))
	}
	w.closeAll()
	if closed[8] != 1 {
		t.Fatal("shutdown did not close remaining owner")
	}
}

func TestPreparationRejectsEndedOwner(t *testing.T) {
	w := newHTTPUprobeWorker(nil, nil, "", nil, nil)
	w.tracking = testTracking{members: map[uint64]uint64{1: 8}}
	for _, tc := range []struct {
		name  string
		owner uint64
	}{
		{name: "zero owner rejected"},
		{name: "old lifetime rejected after rebind", owner: 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := w.prepareFile(t.Context(), nil, nil, 1, tc.owner); !errors.Is(err, errHTTPTrackingEnded) {
				t.Fatalf("late preparation: %v", err)
			}
		})
	}
}
