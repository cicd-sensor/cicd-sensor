package joblogs

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

const DebugRuntimeEventLogFilename = "runtime_event_log.json.gz"
const GitHubActionsDebugOutputDir = "/home/runner/work/_temp/cicd_sensor_debug"

// DebugOutput writes local best-effort debug artifacts for hosted standalone
// jobs. Runtime event log is written as one gzip stream and closed when the
// action requests the project result.
type DebugOutput struct {
	mu     sync.Mutex
	logger *slog.Logger
	dir    string
	file   *os.File
	bufw   *bufio.Writer
	zw     *gzip.Writer
	closed bool
}

func NewGitHubActionsDebugOutput(logger *slog.Logger) (*DebugOutput, error) {
	return newDebugOutput(logger, GitHubActionsDebugOutputDir)
}

// NewDebugOutputForTesting creates a DebugOutput rooted at a caller-provided
// directory. Production code should use NewGitHubActionsDebugOutput so debug
// mode cannot be used as an arbitrary path write primitive.
func NewDebugOutputForTesting(logger *slog.Logger, dir string) (*DebugOutput, error) {
	return newDebugOutput(logger, dir)
}

func newDebugOutput(logger *slog.Logger, dir string) (*DebugOutput, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create debug output dir %s: %w", dir, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open debug output root %s: %w", dir, err)
	}
	defer root.Close()
	file, err := root.OpenFile(DebugRuntimeEventLogFilename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filepath.Join(dir, DebugRuntimeEventLogFilename), err)
	}
	bufw := bufio.NewWriterSize(file, 256*1024)
	return &DebugOutput{
		logger: logger,
		dir:    dir,
		file:   file,
		bufw:   bufw,
		zw:     gzip.NewWriter(bufw),
	}, nil
}

func (o *DebugOutput) WriteRuntimeEventPayload(ctx context.Context, payload []byte) error {
	if o == nil || len(payload) == 0 {
		return nil
	}
	if err := o.writeRuntimeEventPayload(payload); err != nil {
		if o.logger != nil {
			o.logger.WarnContext(ctx, "debug_runtime_event_write_failed",
				"path", filepath.Join(o.dir, DebugRuntimeEventLogFilename),
				"error", err,
			)
		}
		return err
	}
	return nil
}

func (o *DebugOutput) writeRuntimeEventPayload(payload []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.closed {
		return nil
	}
	if _, err := o.zw.Write(payload); err != nil {
		return fmt.Errorf("write gzip payload: %w", err)
	}
	if _, err := o.zw.Write([]byte("\n")); err != nil {
		return fmt.Errorf("write gzip newline: %w", err)
	}
	return nil
}

func (o *DebugOutput) Close(_ context.Context) error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.closed {
		return nil
	}
	o.closed = true

	var errs []error
	if o.zw != nil {
		if err := o.zw.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close gzip writer: %w", err))
		}
		o.zw = nil
	}
	if o.bufw != nil {
		if err := o.bufw.Flush(); err != nil {
			errs = append(errs, fmt.Errorf("flush debug output buffer: %w", err))
		}
		o.bufw = nil
	}
	if o.file != nil {
		if err := o.file.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close debug output file: %w", err))
		}
		o.file = nil
	}
	return errors.Join(errs...)
}
