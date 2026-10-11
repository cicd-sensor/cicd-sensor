//go:build linux

package kernelio

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
	"github.com/cilium/ebpf/link"
)

type notifyCloseLink struct {
	link.Link
	notify func()
}

func (l notifyCloseLink) Close() error { l.notify(); return nil }

func TestSubmitPreparation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name           string
		full, canceled bool
		process        httpprepare.Process
		want           error
	}{
		{name: "full queue rejects immediately", full: true, process: httpprepare.Process{PID: 1}, want: errHTTPPreparationQueueFull},
		{name: "canceled caller does not enqueue", canceled: true, process: httpprepare.Process{PID: 1}, want: context.Canceled},
		{name: "invalid PID is rejected", process: httpprepare.Process{PID: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newHTTPUprobeWorker(nil, nil, t.TempDir(), nil, nil)
			if tc.full {
				for range cap(w.preparationRequests) {
					w.preparationRequests <- &httpPreparationRequest{}
				}
			}
			before := len(w.preparationRequests)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			err := w.submitPreparation(ctx, tc.process)
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
			if len(w.preparationRequests) != before {
				t.Fatal("rejected request was queued")
			}
		})
	}
	t.Run("caller cancellation prevents queued filesystem work", func(t *testing.T) {
		w := newHTTPUprobeWorker(nil, nil, t.TempDir(), nil, nil)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- w.submitPreparation(ctx, httpprepare.Process{PID: os.Getpid()}) }()
		r := <-w.preparationRequests
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		// No mmap/tracking state is configured: reaching either would fail differently.
		w.prepareRequest(t.Context(), r)
		if err := <-r.done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("absent worker still bounds caller waiting", func(t *testing.T) {
		w := newHTTPUprobeWorker(nil, nil, t.TempDir(), nil, nil)
		if err := w.submitPreparation(t.Context(), httpprepare.Process{PID: os.Getpid()}); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	})
}

func TestPrepareHTTPDisabled(t *testing.T) {
	if err := (&LinuxKernelIO{}).PrepareHTTP(t.Context(), httpprepare.Process{PID: os.Getpid()}); !errors.Is(err, ErrNotSupported) {
		t.Fatal(err)
	}
}

func TestPrepareProcessGone(t *testing.T) {
	w := newHTTPUprobeWorker(nil, nil, t.TempDir(), nil, nil)
	r := &httpPreparationRequest{ctx: t.Context(), process: httpprepare.Process{PID: 2147483647}}
	if err := w.prepareProcess(t.Context(), r); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestPrepareProcessUntrackedClosesProcFiles(t *testing.T) {
	w := newHTTPUprobeWorker(nil, nil, "/sys/fs/cgroup", nil, nil)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		r := &httpPreparationRequest{ctx: t.Context(), process: httpprepare.Process{PID: os.Getpid()}}
		if err := w.prepareProcess(t.Context(), r); !errors.Is(err, errHTTPTrackingEnded) {
			t.Fatal(err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("FDs before=%d after=%d", len(before), len(after))
	}
}
