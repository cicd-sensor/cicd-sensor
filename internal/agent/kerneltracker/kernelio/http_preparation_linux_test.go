//go:build linux

package kernelio

import (
	"context"
	"errors"
	"os"
	"testing"

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
			w := newHTTPUprobeWorker(nil, nil, t.TempDir(), nil, nil)
			w.tracking = testTracking{members: map[uint64]uint64{1: 7}}
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
			err := w.submitPreparation(ctx, files, "", 1)
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
			for _, f := range files {
				requirePreparationFileClosed(t, f)
			}
		})
	}
	t.Run("accepted request survives caller timeout until worker cleanup", func(t *testing.T) {
		w := newHTTPUprobeWorker(nil, nil, t.TempDir(), nil, nil)
		w.tracking = testTracking{members: map[uint64]uint64{1: 7}}
		f := preparationTestFile(t)
		ctx, cancel := context.WithCancel(t.Context())
		files := []*os.File{f}
		done := make(chan error, 1)
		go func() { err := w.submitPreparation(ctx, files, "", 1); done <- err }()
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
		w := newHTTPUprobeWorker(nil, nil, t.TempDir(), nil, nil)
		w.tracking = testTracking{members: map[uint64]uint64{1: 7}}
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

func TestPrepareHTTPFilesClosesRejectedDescriptors(t *testing.T) {
	for _, tc := range []struct {
		name             string
		missing, enabled bool
	}{
		{name: "missing membership closes targets", missing: true},
		{name: "disabled capture closes both FD classes"},
		{name: "invalid membership closes both FD classes", enabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := preparationTestFile(t)
			var membership *os.File
			if !tc.missing {
				membership = preparationTestFile(t)
			}
			ki := &LinuxKernelIO{}
			if tc.enabled {
				ki.httpUprobeWorker = newHTTPUprobeWorker(nil, nil, t.TempDir(), nil, nil)
				ki.httpUprobeWorker.control = &uprobeControl{}
			}
			if err := ki.PrepareHTTPFiles(t.Context(), []*os.File{target}, "test", membership); err == nil {
				t.Fatal("invalid request accepted")
			}
			requirePreparationFileClosed(t, target)
			if membership != nil {
				requirePreparationFileClosed(t, membership)
			}
		})
	}
}

// Cleanup belongs to the worker even when its caller has already stopped waiting.
func TestPrepareRequestClosesBatchBeforeReply(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		cancelCaller bool
		cancelWorker bool
		want         error
	}{
		{name: "classification failure closes every file", want: ErrNotSupported},
		{name: "caller cancellation closes unprocessed files", cancelCaller: true, want: context.Canceled},
		{name: "worker cancellation closes unprocessed files", cancelWorker: true, want: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newHTTPUprobeWorker(nil, nil, t.TempDir(), nil, nil)
			w.tracking = testTracking{members: map[uint64]uint64{1: 7}}
			callerCtx, cancelCaller := context.WithCancel(t.Context())
			defer cancelCaller()
			workerCtx, cancelWorker := context.WithCancel(t.Context())
			defer cancelWorker()
			if tc.cancelCaller {
				cancelCaller()
			}
			if tc.cancelWorker {
				cancelWorker()
			}
			files := []*os.File{preparationTestFile(t), preparationTestFile(t)}
			for _, f := range files {
				if _, err := f.WriteString("target"); err != nil {
					t.Fatal(err)
				}
			}
			r := &httpPreparationRequest{cgroupID: 1, owner: 7, ctx: callerCtx, files: files, done: make(chan error, 1)}
			go w.prepareRequest(workerCtx, r)
			if err := <-r.done; !errors.Is(err, tc.want) {
				t.Fatalf("reply=%v want=%v", err, tc.want)
			}
			for _, f := range files {
				requirePreparationFileClosed(t, f)
			}
		})
	}
}
