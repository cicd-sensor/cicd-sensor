package httpprepare

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

// SocketPath keeps descriptor transfer separate from job-facing HTTP routes.
func SocketPath(agentSocket string) string { return agentSocket + ".http-preparation" }

// Preparation bounds producers doing potentially blocking filesystem I/O.
// Slots stay occupied until the operation really finishes, even after timeout.
// Classification and links remain owned by the supplied KernelIO preparer.
type Preparation struct {
	slots  chan struct{}
	local  kernelio.HTTPFilePreparer
	socket string
	logger *slog.Logger
}

// NewLocal connects inventory directly to the Agent-owned worker.
func NewLocal(preparer kernelio.HTTPFilePreparer, logger *slog.Logger) *Preparation {
	return &Preparation{slots: make(chan struct{}, MaxConcurrent), local: preparer, logger: logger}
}

// NewRemote connects a node-side producer to the descriptor-transfer socket.
func NewRemote(agentSocket string, logger *slog.Logger) *Preparation {
	return &Preparation{slots: make(chan struct{}, MaxConcurrent), socket: SocketPath(agentSocket), logger: logger}
}

// Prepare runs bounded inventory and waits only until the common deadline.
func (p *Preparation) Prepare(ctx context.Context, root string, source string) error {
	return p.PrepareResolved(ctx, func(context.Context) (string, error) {
		return root, nil
	}, source)
}

// RootResolver selects the process root. It runs
// within Preparation's admission slot and may outlive the caller's deadline.
type RootResolver func(context.Context) (string, error)

// PrepareResolved includes runtime inspection in the same budget and retained
// slot as inventory. Remote preparation connects before invoking resolve so
// disabled HTTP capture performs no runtime inspection or filesystem scan.
func (p *Preparation) PrepareResolved(ctx context.Context, resolve RootResolver, source string) error {
	ctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()
	select {
	case p.slots <- struct{}{}:
	default:
		return errors.New("HTTP preparation producer limit")
	}
	done := make(chan error, 1)
	started := time.Now()
	go func() {
		var err error
		defer func() {
			<-p.slots
			done <- err
		}()
		if p.local != nil {
			root, resolveErr := resolve(ctx)
			if resolveErr != nil || ctx.Err() != nil {
				err = errors.Join(resolveErr, ctx.Err())
				return
			}
			files, scanErr := OpenFiles(ctx, root)
			prepareErr := p.local.PrepareHTTPFiles(ctx, files, source)
			err = errors.Join(scanErr, prepareErr)
		} else {
			err = prepareRemote(ctx, p.socket, resolve)
		}
	}()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		err = ctx.Err()
	}
	if p.logger != nil {
		p.logger.DebugContext(ctx, "http_preparation_callback", "source", source, "elapsed", time.Since(started), "error", err)
	}
	return err
}

// FileHandler adopts every received descriptor, including on an error.
type FileHandler func(context.Context, []*os.File, string) error
