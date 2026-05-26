// Copyright 2024-2025 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package thread

import (
	"context"
	"errors"
	"runtime"
	"sync"
)

var defaultParallelism = runtime.GOMAXPROCS(0)

// Parallelize runs the jobs in parallel.
//
// Returns the combined error from the jobs.
func Parallelize(ctx context.Context, jobs []func(context.Context) error, options ...ParallelizeOption) error {
	parallelizeOptions := newParallelizeOptions()
	for _, option := range options {
		option(parallelizeOptions)
	}
	switch len(jobs) {
	case 0:
		return nil
	case 1:
		return jobs[0](ctx)
	}
	parallelism := parallelizeOptions.parallelism
	if parallelism < 1 {
		parallelism = defaultParallelism
	}
	var cancel context.CancelFunc
	if parallelizeOptions.cancelOnFailure {
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
	}
	semaphoreC := make(chan struct{}, parallelism)
	var retErr error
	var wg sync.WaitGroup
	var lock sync.Mutex
	var stop bool
	for _, job := range jobs {
		if stop {
			break
		}
		// We always want context cancellation/deadline expiration to take
		// precedence over the semaphore unblocking, but select statements choose
		// among the unblocked non-default cases pseudorandomly. To correctly
		// enforce precedence, use a similar pattern to the check-lock-check
		// pattern common with sync.RWMutex: check the context twice, and only do
		// the semaphore-protected work in the innermost default case.
		select {
		case <-ctx.Done():
			stop = true
			retErr = errors.Join(retErr, ctx.Err())
		case semaphoreC <- struct{}{}:
			select {
			case <-ctx.Done():
				stop = true
				retErr = errors.Join(retErr, ctx.Err())
			default:
				job := job
				wg.Go(func() {
					if err := job(ctx); err != nil {
						lock.Lock()
						retErr = errors.Join(retErr, err)
						lock.Unlock()
						if cancel != nil {
							cancel()
						}
					}
					// This will never block.
					<-semaphoreC
				})
			}
		}
	}
	wg.Wait()
	return retErr
}

// ParallelizeOption is an option to Parallelize.
type ParallelizeOption func(*parallelizeOptions)

// WithParallelism returns a new ParallelizeOption that will run up to the given
// number of goroutines simultaneously.
//
// Values less than 1 are ignored.
//
// The default is runtime.GOMAXPROCS(0).
func WithParallelism(parallelism int) ParallelizeOption {
	return func(parallelizeOptions *parallelizeOptions) {
		parallelizeOptions.parallelism = parallelism
	}
}

// ParallelizeWithCancelOnFailure returns a new ParallelizeOption that will attempt
// to cancel all other jobs via context cancellation if any job fails.
func ParallelizeWithCancelOnFailure() ParallelizeOption {
	return func(parallelizeOptions *parallelizeOptions) {
		parallelizeOptions.cancelOnFailure = true
	}
}

type parallelizeOptions struct {
	parallelism     int
	cancelOnFailure bool
}

func newParallelizeOptions() *parallelizeOptions {
	return &parallelizeOptions{}
}
