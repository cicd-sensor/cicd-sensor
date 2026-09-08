package httpprepare

import (
	"context"
	"errors"
	"log/slog"
	"net"
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
// extraBinDirectories contains selected absolute directories, never a workspace
// walk. The caller's source is a fixed diagnostic label, not arbitrary metadata.
func (p *Preparation) Prepare(ctx context.Context, root string, extraBinDirectories []string, options kernelio.HTTPPreparationOptions) error {
	ctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()
	select {
	case p.slots <- struct{}{}:
	default:
		return errors.New("HTTP preparation producer limit")
	}
	done := make(chan error, 1)
	started := time.Now()
	// Copy small caller-owned metadata because this operation can outlive caller.
	extra := append([]string(nil), extraBinDirectories[:min(len(extraBinDirectories), maxDirectories)]...)
	go func() {
		defer func() { <-p.slots }()
		var err error
		if p.local != nil {
			files, stats, scanErr := OpenFiles(ctx, root, extra)
			_, prepareErr := p.local.PrepareHTTPFiles(ctx, files, options)
			err = errors.Join(scanErr, prepareErr)
			if p.logger != nil {
				p.logger.DebugContext(ctx, "http_preparation_inventory", "source", options.Source, "directories", stats.Directories, "entries", stats.Entries, "opened", stats.Opened, "truncated", stats.Truncated)
			}
		} else {
			err = prepareRemote(ctx, p.socket, root, extra, options.Source)
		}
		done <- err
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
type FileHandler func(context.Context, []*os.File, kernelio.HTTPPreparationOptions) (kernelio.HTTPPreparationResult, error)

// Available avoids Docker inspect work when the Agent has HTTP capture disabled.
// It is a best-effort local socket check; preparation still handles later failure.
func (p *Preparation) Available(ctx context.Context) error {
	if p.local != nil {
		return nil
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unixpacket", p.socket)
	if err == nil {
		_ = c.Close()
	}
	return err
}
