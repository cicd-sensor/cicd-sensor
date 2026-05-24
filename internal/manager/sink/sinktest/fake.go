// Package sinktest provides in-memory sink implementations for manager tests.
package sinktest

import (
	"context"
	"fmt"
	"sync"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink"
)

// Sink is a concurrent-safe in-memory sink for unit tests.
type Sink struct {
	name string

	mu      sync.Mutex
	batches []sink.IngestLogBatch
	errors  []error
	calls   int
	closes  int
	policy  sink.FlushPolicy
}

// New creates an in-memory sink with the given name.
func New(name string) *Sink {
	return &Sink{
		name: name,
	}
}

func (s *Sink) Write(ctx context.Context, batch sink.IngestLogBatch) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if len(s.errors) > 0 {
		err := s.errors[0]
		s.errors = s.errors[1:]
		if err != nil {
			return err
		}
	}
	batch.Body = append([]byte(nil), batch.Body...)
	s.batches = append(s.batches, batch)
	return nil
}

func (s *Sink) Name() string {
	return s.name
}

func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closes++
	return nil
}

func (s *Sink) FlushPolicy(logtype.LogType) sink.FlushPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.policy == (sink.FlushPolicy{}) {
		return sink.FlushPolicy{FlushThresholdBytes: 1, FlushIntervalSeconds: 1}
	}
	return s.policy
}

// SetFlushPolicy configures the policy returned by FlushPolicy.
func (s *Sink) SetFlushPolicy(policy sink.FlushPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = policy
}

// Batches returns a copy of batches written so far.
func (s *Sink) Batches() []sink.IngestLogBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sink.IngestLogBatch, len(s.batches))
	for i, batch := range s.batches {
		batch.Body = append([]byte(nil), batch.Body...)
		out[i] = batch
	}
	return out
}

// SetError makes the next Write fail with err.
func (s *Sink) SetError(err error) {
	s.SetErrors(err)
}

// SetErrors configures the next Writes to return the given errors in order.
func (s *Sink) SetErrors(errs ...error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errors = append([]error(nil), errs...)
}

// Calls returns the number of Write calls.
func (s *Sink) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Closes returns the number of Close calls.
func (s *Sink) Closes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

func (s *Sink) String() string {
	return fmt.Sprintf("fakeSink(%s)", s.name)
}
