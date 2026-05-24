package joblogs

import (
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebugOutputWritesSingleReadableGzipStreamAfterClose(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	output, err := NewDebugOutputForTesting(slog.Default(), dir)
	if err != nil {
		t.Fatalf("NewDebugOutputForTesting: %v", err)
	}
	if err := output.WriteRuntimeEventPayload(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("write first record: %v", err)
	}
	if err := output.WriteRuntimeEventPayload(context.Background(), []byte(`{"n":2}`)); err != nil {
		t.Fatalf("write second record: %v", err)
	}
	if err := output.Close(context.Background()); err != nil {
		t.Fatalf("close debug output: %v", err)
	}

	if got, want := readDebugGzip(t, dir), "{\"n\":1}\n{\"n\":2}\n"; got != want {
		t.Fatalf("debug gzip body:\ngot  %q\nwant %q", got, want)
	}
}

func TestDebugOutputCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	output, err := NewDebugOutputForTesting(slog.Default(), t.TempDir())
	if err != nil {
		t.Fatalf("NewDebugOutputForTesting: %v", err)
	}
	if err := output.WriteRuntimeEventPayload(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("write record: %v", err)
	}
	if err := output.Close(context.Background()); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := output.Close(context.Background()); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestDebugOutputIgnoresWritesAfterClose(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	output, err := NewDebugOutputForTesting(slog.Default(), dir)
	if err != nil {
		t.Fatalf("NewDebugOutputForTesting: %v", err)
	}
	if err := output.WriteRuntimeEventPayload(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("write record: %v", err)
	}
	if err := output.Close(context.Background()); err != nil {
		t.Fatalf("close debug output: %v", err)
	}
	before := readDebugGzip(t, dir)
	if err := output.WriteRuntimeEventPayload(context.Background(), []byte(`{"late":true}`)); err != nil {
		t.Fatalf("late write: %v", err)
	}
	after := readDebugGzip(t, dir)
	if before != after {
		t.Fatalf("late write changed gzip body:\nbefore %q\nafter  %q", before, after)
	}
	if strings.Contains(after, "late") {
		t.Fatalf("late record was written after close: %q", after)
	}
}

func readDebugGzip(t *testing.T, dir string) string {
	t.Helper()

	file, err := os.Open(filepath.Join(dir, DebugRuntimeEventLogFilename))
	if err != nil {
		t.Fatalf("open debug gzip: %v", err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close gzip reader: %v", err)
	}
	return string(body)
}
