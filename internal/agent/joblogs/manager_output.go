package joblogs

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
)

type managerOutput struct {
	mu sync.Mutex
	// closed gates new streaming emits while a close request is being sent.
	closed   bool
	requests chan managerOutputRequest
	done     chan struct{}
	dropped  atomic.Uint64
}

func newManagerOutput(
	logger *slog.Logger,
	sendBatch func(context.Context, managerclient.LogBatch) error,
	identity jobcontext.JobIdentity,
	scope jobcontext.ScopeType,
	logType managerv1beta1.LogType,
	setting *managerv1beta1.OutputSetting,
	channelCap int,
) *managerOutput {
	if sendBatch == nil {
		return nil
	}
	worker := newManagerWorker(managerWorkerConfig{
		logger:    logger,
		sendBatch: sendBatch,
		identity:  identity,
		scope:     protoconv.ToProtoScope(scope),
		logType:   logType,
		setting:   setting,
		now:       time.Now,
	})
	out := &managerOutput{
		requests: make(chan managerOutputRequest, channelCap),
		done:     make(chan struct{}),
	}
	go worker.run(out.requests, out.done)
	return out
}

func (s *managerOutput) Emit(ctx context.Context, payload []byte) error {
	if s == nil || len(payload) == 0 {
		return nil
	}
	req := managerOutputRequest{ctx: ctx, payload: append([]byte(nil), payload...)}
	return s.tryEnqueueRequest(ctx, req)
}

func (s *managerOutput) EmitAndClose(ctx context.Context, payload []byte) error {
	return s.close(ctx, payload)
}

func (s *managerOutput) Close(ctx context.Context) error {
	return s.close(ctx, nil)
}

func (s *managerOutput) close(ctx context.Context, payload []byte) error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	reply := make(chan error, 1)
	req := managerOutputRequest{ctx: ctx, close: true, reply: reply}
	if len(payload) > 0 {
		req.payload = append([]byte(nil), payload...)
	}
	if err := s.enqueueRequest(ctx, req); err != nil {
		s.mu.Lock()
		s.closed = false
		s.mu.Unlock()
		return err
	}
	return waitJobLogOutputClose(ctx, reply, s.done)
}

func (s *managerOutput) tryEnqueueRequest(ctx context.Context, req managerOutputRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errManagerOutputClosed
	}
	select {
	case s.requests <- req:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		s.dropped.Add(1)
		return errManagerOutputBacklogFull
	}
}

func (s *managerOutput) droppedCount() uint64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

func (s *managerOutput) enqueueRequest(ctx context.Context, req managerOutputRequest) error {
	select {
	case s.requests <- req:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return nil
	}
}

func waitJobLogOutputClose(ctx context.Context, reply <-chan error, done <-chan struct{}) error {
	select {
	case err := <-reply:
		return err
	case <-done:
		select {
		case err := <-reply:
			return err
		default:
			return nil
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}
