//go:build linux

package httpprepare

import (
	"context"
	"errors"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

type stalledPreparer struct {
	entered chan struct{}
	release chan struct{}
}

func (p *stalledPreparer) PrepareHTTPFiles(_ context.Context, files []*os.File, _ string) error {
	defer CloseFiles(files)
	p.entered <- struct{}{}
	<-p.release
	return nil
}

func TestPreparationRetainsSlots(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout bool
		resolve bool
	}{
		{name: "caller cancellation cannot multiply blocked worker"},
		{name: "caller deadline cannot multiply blocked worker", timeout: true},
		{name: "caller cancellation cannot multiply blocked resolver", resolve: true},
		{name: "caller deadline cannot multiply blocked resolver", timeout: true, resolve: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			synctest.Test(t, func(t *testing.T) {
				worker := &stalledPreparer{make(chan struct{}, MaxConcurrent+1), make(chan struct{})}
				p := NewLocal(worker, nil)
				prepare := func(ctx context.Context) error {
					if !tc.resolve {
						return p.Prepare(ctx, root, "")
					}
					return p.PrepareResolved(ctx, func(context.Context) (string, error) {
						worker.entered <- struct{}{}
						<-worker.release
						return root, nil
					}, "")
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				returned := make(chan error, MaxConcurrent)
				for range MaxConcurrent {
					go func() { returned <- prepare(ctx) }()
				}
				for range MaxConcurrent {
					<-worker.entered
				}
				if tc.timeout {
					time.Sleep(Budget)
				} else {
					cancel()
				}
				for range MaxConcurrent {
					if err := <-returned; err == nil {
						t.Fatal("caller must stop waiting")
					}
				}
				if err := prepare(t.Context()); err == nil {
					t.Fatal("blocked work exceeded admission limit")
				}
				if len(worker.entered) != 0 {
					t.Fatal("rejected request reached worker")
				}
				close(worker.release)
				synctest.Wait()
				if len(p.slots) != 0 {
					t.Fatal("completed work retained slots")
				}
				if err := prepare(t.Context()); err != nil {
					t.Fatalf("capacity did not recover: %v", err)
				}
			})
		})
	}
}

func TestPreparationResolverFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remote bool
	}{
		{name: "root resolution error releases producer slot"},
		{name: "unavailable receiver skips runtime inspection", remote: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			want := errors.New("root unavailable")
			called := false
			p := NewLocal(&stalledPreparer{}, nil)
			if tc.remote {
				p = NewRemote(t.TempDir()+"/absent.sock", nil)
			}
			err := p.PrepareResolved(t.Context(), func(context.Context) (string, error) {
				called = true
				return "", want
			}, "docker-start")
			if tc.remote {
				if err == nil || called {
					t.Fatalf("called=%v err=%v", called, err)
				}
			} else if !called || !errors.Is(err, want) {
				t.Fatalf("called=%v err=%v", called, err)
			}
			if len(p.slots) != 0 {
				t.Fatal("failed request retained producer slot")
			}
		})
	}
}
