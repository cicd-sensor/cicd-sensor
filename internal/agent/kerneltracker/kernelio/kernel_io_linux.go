//go:build linux

package kernelio

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// LinuxKernelIO owns BPF program, map, and ring buffer I/O.
type LinuxKernelIO struct {
	logger          *slog.Logger
	objs            bpfprog.BPFProgramObjects
	links           []link.Link
	reader          *ringbuf.Reader
	cancelLoop      context.CancelFunc
	closeReaderOnce sync.Once
	// loopWG tracks goroutines spawned by StartKernelSampleLoop. Close
	// must wait for them to exit before tearing down objs / map FDs;
	// otherwise watchRingbufDrops can race objs.Close on a Map.Lookup
	// (-race detected this on the Phase 3 integration run).
	loopWG sync.WaitGroup
}

// NewLinux loads the BPF objects, attaches programs, and opens the sample ring buffer.
func NewLinux(logger *slog.Logger, config Config) (kernelIO *LinuxKernelIO, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	if config.CgroupV2RootPath == "" {
		return nil, errors.New("cgroup v2 root path is required")
	}

	kernelIO = &LinuxKernelIO{
		logger: logger.With("component", "bpf_kernel_io"),
	}

	spec, err := bpfprog.LoadBPFProgram()
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}
	if err := configureBPFProgramSpec(spec); err != nil {
		return nil, fmt.Errorf("configure bpf program spec: %w", err)
	}
	if err := spec.LoadAndAssign(&kernelIO.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	// NewLinux fails fast on any attach/open error, but earlier steps may
	// already have loaded objects or attached links. Roll those back here
	// because no caller-owned LinuxKernelIO exists on failure.
	defer func() {
		if err == nil {
			return
		}
		_ = kernelIO.Close()
	}()

	// fentry/security_file_open is used instead of BPF LSM so deployments do
	// not need lsm=..., Rename/symlink observation stays in inode hooks
	// because security_path_* cannot use bpf_d_path in container filesystems.
	for _, attach := range []struct {
		name    string
		program *ebpf.Program
	}{
		{name: "sched_process_fork", program: kernelIO.objs.HandleSchedProcessFork},
		{name: "sched_process_exec", program: kernelIO.objs.HandleSchedProcessExec},
		{name: "cgroup_mkdir", program: kernelIO.objs.HandleCgroupMkdir},
		{name: "cgroup_attach_task", program: kernelIO.objs.HandleCgroupAttachTask},
		{name: "cgroup_rmdir", program: kernelIO.objs.HandleCgroupRmdir},
		{name: "security_file_open", program: kernelIO.objs.HandleSecurityFileOpen},
		{name: "security_inode_unlink", program: kernelIO.objs.HandleSecurityInodeUnlink},
		{name: "security_inode_rmdir", program: kernelIO.objs.HandleSecurityInodeRmdir},
		{name: "security_inode_rename", program: kernelIO.objs.HandleSecurityInodeRename},
		{name: "security_inode_link", program: kernelIO.objs.HandleSecurityInodeLink},
		{name: "security_inode_symlink", program: kernelIO.objs.HandleSecurityInodeSymlink},
		{name: "udp_sendmsg", program: kernelIO.objs.HandleUdpSendmsg},
		{name: "udpv6_sendmsg", program: kernelIO.objs.HandleUdpv6Sendmsg},
		{name: "tcp_sendmsg", program: kernelIO.objs.HandleTcpSendmsg},
		{name: "unix_stream_sendmsg", program: kernelIO.objs.HandleUnixStreamSendmsg},
		{name: "unix_stream_connect", program: kernelIO.objs.HandleUnixStreamConnect},
		{name: "unix_dgram_connect", program: kernelIO.objs.HandleUnixDgramConnect},
	} {
		attached, err := link.AttachTracing(link.TracingOptions{Program: attach.program})
		if err != nil {
			return nil, fmt.Errorf("attach %s tracing program: %w", attach.name, err)
		}
		kernelIO.links = append(kernelIO.links, attached)
	}

	// Cgroup programs use AttachCgroup because they run from the cgroup v2
	// root, unlike the tracing/fentry programs above.
	// cgroup/connect{4,6} is attached once to the cgroup v2 root. Per-job
	// dynamic attach would race with bind/unbind and duplicate kernel work.
	for _, attach := range []struct {
		name       string
		attachType ebpf.AttachType
		program    *ebpf.Program
	}{
		{name: "cgroup/connect4", attachType: ebpf.AttachCGroupInet4Connect, program: kernelIO.objs.HandleCgroupConnect4},
		{name: "cgroup/connect6", attachType: ebpf.AttachCGroupInet6Connect, program: kernelIO.objs.HandleCgroupConnect6},
	} {
		attached, err := link.AttachCgroup(link.CgroupOptions{
			Path:    config.CgroupV2RootPath,
			Attach:  attach.attachType,
			Program: attach.program,
		})
		if err != nil {
			return nil, fmt.Errorf("attach %s program: %w", attach.name, err)
		}
		kernelIO.links = append(kernelIO.links, attached)
	}

	reader, err := ringbuf.NewReader(kernelIO.objs.Events)
	if err != nil {
		return nil, fmt.Errorf("open events ringbuf: %w", err)
	}
	kernelIO.reader = reader
	return kernelIO, nil
}
