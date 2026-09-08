//go:build linux

package httpprepare

import (
	"context"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

type stalledPreparer struct {
	entered chan struct{}
	release chan struct{}
}

func (p *stalledPreparer) PrepareHTTPFiles(_ context.Context, files []*os.File, _ kernelio.HTTPPreparationOptions) (kernelio.HTTPPreparationResult, error) {
	defer CloseFiles(files)
	p.entered <- struct{}{}
	<-p.release
	return kernelio.HTTPPreparationResult{}, nil
}

func TestPreparationRetainsSlots(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout bool
	}{
		{"caller cancellation cannot multiply blocked work", false},
		{"caller deadline cannot multiply blocked work", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			synctest.Test(t, func(t *testing.T) {
				worker := &stalledPreparer{make(chan struct{}, MaxConcurrent+1), make(chan struct{})}
				p := NewLocal(worker, nil)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				returned := make(chan error, MaxConcurrent)
				for range MaxConcurrent {
					go func() { returned <- p.Prepare(ctx, root, nil, kernelio.HTTPPreparationOptions{}) }()
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
				if err := p.Prepare(t.Context(), root, nil, kernelio.HTTPPreparationOptions{}); err == nil {
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
				if err := p.Prepare(t.Context(), root, nil, kernelio.HTTPPreparationOptions{}); err != nil {
					t.Fatalf("capacity did not recover: %v", err)
				}
			})
		})
	}
}
