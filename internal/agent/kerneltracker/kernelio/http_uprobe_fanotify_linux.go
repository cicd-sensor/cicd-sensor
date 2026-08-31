//go:build linux

package kernelio

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	httpUprobePermissionDeadline = 250 * time.Millisecond
	fanotifyReadBufferSize       = 64 * 1024
)

type httpUprobeFanotify struct {
	fd              int
	logger          *slog.Logger
	cgroupRootPath  string
	trackedCgroups  *ebpf.Map
	worker          *httpUprobeWorker
	closeOnce       sync.Once
	permissionWaits sync.WaitGroup
	busyCount       atomic.Uint64
	timeoutCount    atomic.Uint64
	trackingErrors  atomic.Uint64
}

func newHTTPUprobeFanotify(
	logger *slog.Logger,
	cgroupRootPath string,
	trackedCgroups *ebpf.Map,
	worker *httpUprobeWorker,
) (*httpUprobeFanotify, error) {
	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_PRE_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC,
	)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}
	if err := unix.FanotifyMark(
		fd,
		unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM,
		unix.FAN_OPEN_EXEC_PERM,
		unix.AT_FDCWD,
		"/",
	); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("mark root filesystem: %w", err)
	}
	return &httpUprobeFanotify{
		fd:             fd,
		logger:         logger,
		cgroupRootPath: cgroupRootPath,
		trackedCgroups: trackedCgroups,
		worker:         worker,
	}, nil
}

func (f *httpUprobeFanotify) close() error {
	if f == nil {
		return nil
	}
	var closeErr error
	f.closeOnce.Do(func() {
		closeErr = unix.Close(f.fd)
	})
	if errors.Is(closeErr, unix.EBADF) {
		return nil
	}
	return closeErr
}

func (f *httpUprobeFanotify) run(ctx context.Context) {
	defer func() {
		// Closing the group releases every unresolved permission event. Do this
		// before waiting for response goroutines when the reader itself fails.
		_ = f.close()
		f.permissionWaits.Wait()
	}()

	buffer := make([]byte, fanotifyReadBufferSize)
	for {
		if ctx.Err() != nil {
			return
		}
		pollFDs := []unix.PollFd{{Fd: int32(f.fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(pollFDs, 100)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) || ctx.Err() != nil {
				return
			}
			f.logger.WarnContext(ctx, "http_uprobe_fanotify_poll_failed", "error", err)
			return
		}
		if ready == 0 {
			continue
		}

		n, err := unix.Read(f.fd, buffer)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) || ctx.Err() != nil {
				return
			}
			f.logger.WarnContext(ctx, "http_uprobe_fanotify_read_failed", "error", err)
			return
		}
		if err := f.handleEvents(ctx, buffer[:n]); err != nil {
			f.logger.WarnContext(ctx, "http_uprobe_fanotify_event_failed", "error", err)
			// A malformed batch can still contain permission events that have not
			// been answered. Exit so the deferred group close releases every hold.
			return
		}
	}
}

func (f *httpUprobeFanotify) handleEvents(ctx context.Context, buffer []byte) error {
	for len(buffer) > 0 {
		metadata, eventLength, err := decodeFanotifyMetadata(buffer)
		if err != nil {
			return err
		}
		buffer = buffer[eventLength:]

		if metadata.Mask&unix.FAN_Q_OVERFLOW != 0 {
			f.logger.WarnContext(ctx, "http_uprobe_fanotify_queue_overflow")
			continue
		}
		if metadata.Fd < 0 {
			continue
		}
		eventFile := os.NewFile(uintptr(metadata.Fd), "fanotify-event")
		if eventFile == nil {
			_ = unix.Close(int(metadata.Fd))
			continue
		}
		if metadata.Mask&unix.FAN_OPEN_EXEC_PERM == 0 {
			_ = eventFile.Close()
			continue
		}
		f.handleExecPermission(ctx, metadata.Pid, eventFile)
	}
	return nil
}

func decodeFanotifyMetadata(buffer []byte) (unix.FanotifyEventMetadata, int, error) {
	const metadataSize = unix.FAN_EVENT_METADATA_LEN
	if len(buffer) < metadataSize {
		return unix.FanotifyEventMetadata{}, 0, fmt.Errorf("short fanotify metadata: %d bytes", len(buffer))
	}
	eventLength := int(binary.LittleEndian.Uint32(buffer[0:4]))
	metadataLength := int(binary.LittleEndian.Uint16(buffer[6:8]))
	if eventLength < metadataSize || eventLength > len(buffer) || metadataLength < metadataSize {
		return unix.FanotifyEventMetadata{}, 0, fmt.Errorf(
			"invalid fanotify lengths: event=%d metadata=%d available=%d",
			eventLength,
			metadataLength,
			len(buffer),
		)
	}
	metadata := unix.FanotifyEventMetadata{
		Event_len:    uint32(eventLength),
		Vers:         buffer[4],
		Reserved:     buffer[5],
		Metadata_len: uint16(metadataLength),
		Mask:         binary.LittleEndian.Uint64(buffer[8:16]),
		Fd:           int32(binary.LittleEndian.Uint32(buffer[16:20])),
		Pid:          int32(binary.LittleEndian.Uint32(buffer[20:24])),
	}
	if metadata.Vers != unix.FANOTIFY_METADATA_VERSION {
		return unix.FanotifyEventMetadata{}, 0, fmt.Errorf(
			"fanotify metadata version %d, want %d",
			metadata.Vers,
			unix.FANOTIFY_METADATA_VERSION,
		)
	}
	return metadata, eventLength, nil
}

func (f *httpUprobeFanotify) handleExecPermission(
	ctx context.Context,
	tgid int32,
	eventFile *os.File,
) {
	tracked, err := f.processIsTracked(tgid)
	if err != nil {
		f.warnAtPowerOfTwo(&f.trackingErrors, "http_uprobe_fanotify_cgroup_lookup_failed", "error", err)
		f.allowAndClose(eventFile)
		return
	}
	if !tracked {
		f.allowAndClose(eventFile)
		return
	}

	workerFD, err := unix.FcntlInt(eventFile.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		f.allowAndClose(eventFile)
		return
	}
	workerFile := os.NewFile(uintptr(workerFD), "fanotify-worker-file")
	if workerFile == nil {
		_ = unix.Close(workerFD)
		f.allowAndClose(eventFile)
		return
	}

	request := httpUprobePermissionRequest{
		file: workerFile,
		done: make(chan struct{}),
	}
	if ctx.Err() != nil {
		_ = workerFile.Close()
		f.allowAndClose(eventFile)
		return
	}
	select {
	case f.worker.permissionRequests <- request:
		f.permissionWaits.Add(1)
		go f.awaitPermission(ctx, eventFile, request)
	default:
		_ = workerFile.Close()
		f.warnAtPowerOfTwo(&f.busyCount, "http_uprobe_fanotify_worker_busy")
		f.allowAndClose(eventFile)
	}
}

func (f *httpUprobeFanotify) awaitPermission(
	ctx context.Context,
	eventFile *os.File,
	request httpUprobePermissionRequest,
) {
	defer f.permissionWaits.Done()
	timer := time.NewTimer(httpUprobePermissionDeadline)
	defer timer.Stop()

	select {
	case <-request.done:
	case <-timer.C:
		f.warnAtPowerOfTwo(&f.timeoutCount, "http_uprobe_fanotify_timeout")
	case <-ctx.Done():
	}
	f.allowAndClose(eventFile)
}

func (f *httpUprobeFanotify) allowAndClose(eventFile *os.File) {
	defer eventFile.Close()
	var response [8]byte
	binary.LittleEndian.PutUint32(response[0:4], uint32(eventFile.Fd()))
	binary.LittleEndian.PutUint32(response[4:8], unix.FAN_ALLOW)
	for {
		written, err := unix.Write(f.fd, response[:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err == nil && written == len(response) {
			return
		}
		if errors.Is(err, unix.EBADF) || errors.Is(err, unix.ENOENT) {
			return
		}
		// Linux has no permission-event timeout. If one response cannot be
		// completed, close the group so this and every other hold is released.
		f.logger.Warn("http_uprobe_fanotify_allow_failed", "error", err, "bytes", written)
		_ = f.close()
		return
	}
}

func (f *httpUprobeFanotify) processIsTracked(tgid int32) (bool, error) {
	if tgid <= 0 {
		return false, nil
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", tgid))
	if err != nil {
		return false, err
	}
	cgroupPath, ok := cgroupV2Path(data)
	if !ok {
		return false, errors.New("cgroup v2 entry not found")
	}
	fullPath := filepath.Join(f.cgroupRootPath, strings.TrimPrefix(cgroupPath, "/"))
	var stat unix.Stat_t
	if err := unix.Stat(fullPath, &stat); err != nil {
		return false, err
	}
	var value uint8
	if err := f.trackedCgroups.Lookup(stat.Ino, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func cgroupV2Path(data []byte) (string, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		if cgroupPath, ok := strings.CutPrefix(line, "0::"); ok {
			return cgroupPath, true
		}
	}
	return "", false
}

func (f *httpUprobeFanotify) warnAtPowerOfTwo(counter *atomic.Uint64, message string, args ...any) {
	count := counter.Add(1)
	if count&(count-1) == 0 {
		f.logger.Warn(message, append([]any{"count", count}, args...)...)
	}
}
