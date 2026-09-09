package httpprepare

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
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
// extraBinDirectories contains selected absolute directories, never a workspace
// walk. The caller's source is a fixed diagnostic label, not arbitrary metadata.
func (p *Preparation) Prepare(ctx context.Context, root string, extraBinDirectories []string, options kernelio.HTTPPreparationOptions) error {
	// The bounded metadata copy can outlive the caller after cancellation.
	extra := slices.Clone(extraBinDirectories[:min(len(extraBinDirectories), maxDirectories)])
	return p.PrepareResolved(ctx, func(context.Context) (string, []string, error) {
		return root, extra, nil
	}, options)
}

// RootResolver selects the process root and bounded extra directories. It runs
// within Preparation's admission slot and may outlive the caller's deadline.
type RootResolver func(context.Context) (string, []string, error)

// PrepareResolved includes runtime inspection in the same budget and retained
// slot as inventory. Remote preparation connects before invoking resolve so
// disabled HTTP capture performs no runtime inspection or filesystem scan.
func (p *Preparation) PrepareResolved(ctx context.Context, resolve RootResolver, options kernelio.HTTPPreparationOptions) error {
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
			root, extra, resolveErr := resolve(ctx)
			if resolveErr != nil || ctx.Err() != nil {
				err = errors.Join(resolveErr, ctx.Err())
				return
			}
			files, stats, scanErr := OpenFiles(ctx, root, extra)
			prepareErr := p.local.PrepareHTTPFiles(ctx, files, options)
			err = errors.Join(scanErr, prepareErr)
			if p.logger != nil {
				p.logger.DebugContext(ctx, "http_preparation_inventory", "source", options.Source, "directories", stats.Directories, "entries", stats.Entries, "opened", stats.Opened, "truncated", stats.Truncated)
			}
		} else {
			err = prepareRemote(ctx, p.socket, resolve, options.Source)
		}
	}()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		err = ctx.Err()
	}
	if p.logger != nil {
		p.logger.DebugContext(ctx, "http_preparation_callback", "source", options.Source, "elapsed", time.Since(started), "error", err)
	}
	return err
}

// FileHandler adopts every received descriptor, including on an error.
type FileHandler func(context.Context, []*os.File, kernelio.HTTPPreparationOptions) error
