//go:build linux

package kernelio

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
)

type notifyCloseLink struct {
	link.Link
	notify func()
}

func (l notifyCloseLink) Close() error { l.notify(); return nil }

func preparationTestFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "target")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}
func requirePreparationFileClosed(t *testing.T, f *os.File) {
	t.Helper()
	if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("descriptor not closed: %v", err)
	}
}

func TestSubmitPreparation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		setup    func(*httpUprobeWorker)
		canceled bool
		count    int
		want     error
	}{
		{"full queue closes adopted files", func(w *httpUprobeWorker) {
			for range cap(w.preparationRequests) {
				w.preparationRequests <- &httpPreparationRequest{}
			}
		}, false, 1, errHTTPPreparationQueueFull},
		{"stopped worker closes adopted files", func(w *httpUprobeWorker) { w.shutdownPreparation() }, false, 1, errHTTPPreparationStopped},
		{"canceled caller closes adopted files", func(*httpUprobeWorker) {}, true, 1, context.Canceled},
		{"file cap closes whole batch", func(*httpUprobeWorker) {}, false, MaxHTTPPreparationFiles + 1, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newHTTPUprobeWorker(nil, nil, t.TempDir(), nil, goUprobeTarget{})
			tc.setup(w)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			files := make([]*os.File, tc.count)
			for i := range files {
				files[i] = preparationTestFile(t)
			}
			err := w.submitPreparation(ctx, files, HTTPPreparationOptions{})
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
			for _, f := range files {
				requirePreparationFileClosed(t, f)
			}
		})
	}
	t.Run("accepted request survives caller timeout until worker cleanup", func(t *testing.T) {
		w := newHTTPUprobeWorker(nil, nil, t.TempDir(), nil, goUprobeTarget{})
		f := preparationTestFile(t)
		ctx, cancel := context.WithCancel(t.Context())
		files := []*os.File{f}
		done := make(chan error, 1)
		go func() { err := w.submitPreparation(ctx, files, HTTPPreparationOptions{}); done <- err }()
		r := <-w.preparationRequests
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if _, err := f.Stat(); err != nil {
			t.Fatalf("caller prematurely closed accepted FD: %v", err)
		}
		files[0] = nil // caller storage is reusable after API return
		w.prepareRequest(t.Context(), r)
		requirePreparationFileClosed(t, f)
		w.shutdownPreparation()
	})
	t.Run("shutdown drains queued descriptors and is idempotent", func(t *testing.T) {
		w := newHTTPUprobeWorker(nil, nil, t.TempDir(), nil, goUprobeTarget{})
		f := preparationTestFile(t)
		r := &httpPreparationRequest{files: []*os.File{f}, done: make(chan error, 1)}
		w.preparationRequests <- r
		w.shutdownPreparation()
		w.shutdownPreparation()
		requirePreparationFileClosed(t, f)
		if reply := <-r.done; !errors.Is(reply, errHTTPPreparationStopped) {
			t.Fatal(reply)
		}
	})
}

func TestPreparedTargetRetention(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		grace  time.Duration
		remain bool
	}{
		{name: "unused preparation survives grace", grace: time.Minute, remain: true},
		{name: "expired unused preparation is reclaimed", grace: -time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newReclaimHarness(t)
			id := mappedFileIdentity{inode: 42}
			e := h.attached(id)
			e.protectedUntil = time.Now().Add(tc.grace)
			h.sweep()
			h.sweep()
			if (h.worker.attachedTargets[id] != nil) != tc.remain {
				t.Fatalf("retention mismatch")
			}
		})
	}
	for _, tc := range []struct {
		name     string
		queue    string
		canceled bool
		remain   int
	}{
		{"idle sweep drains a burst of expired targets", "", false, 0},
		{"pending preparation defers close until a fresh sweep", "preparation", false, 512},
		{"pending mapping defers close until a fresh sweep", "mapping", false, 512},
		{"canceled worker keeps links for shutdown", "", true, 512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newReclaimHarness(t)
			for i := range 512 {
				h.attached(mappedFileIdentity{inode: uint64(i + 1)})
			}
			h.sweep()
			switch tc.queue {
			case "preparation":
				h.worker.preparationRequests <- &httpPreparationRequest{}
			case "mapping":
				h.worker.attachCandidates <- httpUprobeAttachCandidate{}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			h.worker.reconcileTargets(ctx, nil)
			if got := len(h.worker.attachedTargets); got != tc.remain {
				t.Fatalf("targets=%d want=%d", got, tc.remain)
			}
			switch tc.queue {
			case "preparation":
				<-h.worker.preparationRequests
			case "mapping":
				<-h.worker.attachCandidates
			}
			h.sweep()
			if len(h.worker.attachedTargets) != 0 {
				t.Fatal("idle sweep left expired targets")
			}
		})
	}
	for _, arrival := range []string{"preparation", "mapping", "cancellation"} {
		t.Run(arrival+" arriving during close yields before next target", func(t *testing.T) {
			t.Parallel()
			h := newReclaimHarness(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			closed := 0
			for i := range 5 {
				e := h.attached(mappedFileIdentity{inode: uint64(i + 1)})
				e.links = []link.Link{notifyCloseLink{notify: func() {
					closed++
					switch arrival {
					case "preparation":
						h.worker.preparationRequests <- &httpPreparationRequest{}
					case "mapping":
						h.worker.attachCandidates <- httpUprobeAttachCandidate{}
					case "cancellation":
						cancel()
					}
				}}}
			}
			h.sweep()
			h.worker.reconcileTargets(ctx, nil)
			if closed != 1 || len(h.worker.attachedTargets) != 4 {
				t.Fatalf("closed=%d retained=%d", closed, len(h.worker.attachedTargets))
			}
		})
	}
}
