//go:build linux

package kernelio

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// LinuxKernelIO owns BPF program, map, and ring buffer I/O.
type LinuxKernelIO struct {
	logger *slog.Logger
	// coll owns every loaded program and map FD. Close tears it down.
	coll *ebpf.Collection
	// objs holds typed map handles assigned from coll so the generated map
	// helpers keep working. Program fields are unused: programs are taken from
	// coll.Programs directly so unattachable ones can be pruned at load time.
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

	// Custom kernels (e.g. Blacksmith CI runners, kernel 6.5.13) do not expose
	// some LSM hook functions for fentry. cilium/ebpf resolves an fentry program's
	// attach target at load time, so an unattachable target fails the whole
	// collection load — not just the later attach step. Drop those programs up
	// front so the agent starts with reduced coverage instead of failing on such
	// kernels. On a fully-capable kernel this prunes nothing.
	pruneUnattachableTracingPrograms(spec, kernelIO.logger)

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}
	kernelIO.coll = coll

	// NewLinux fails fast on any later error; roll back coll / links here because
	// no caller-owned LinuxKernelIO exists on failure.
	defer func() {
		if err == nil {
			return
		}
		_ = kernelIO.Close()
	}()

	// Maps are always present; assign them to the generated struct so the typed
	// map helpers (kernel_io_maps_linux.go) and the loop keep working unchanged.
	kernelIO.objs.Events = coll.Maps["events"]
	kernelIO.objs.PathScratch = coll.Maps["path_scratch"]
	kernelIO.objs.RingbufDropCount = coll.Maps["ringbuf_drop_count"]
	kernelIO.objs.StagingMap = coll.Maps["staging_map"]
	kernelIO.objs.TrackedCgroups = coll.Maps["tracked_cgroups"]

	// fentry/security_file_open is used instead of BPF LSM so deployments do
	// not need lsm=..., Rename/symlink observation stays in inode hooks
	// because security_path_* cannot use bpf_d_path in container filesystems.
	// program is nil when pruned above (not attachable on this kernel) -> skip.
	for _, attach := range []struct {
		name    string
		program *ebpf.Program
	}{
		{name: "sched_process_fork", program: coll.Programs["handle_sched_process_fork"]},
		{name: "sched_process_exec", program: coll.Programs["handle_sched_process_exec"]},
		{name: "cgroup_mkdir", program: coll.Programs["handle_cgroup_mkdir"]},
		{name: "cgroup_attach_task", program: coll.Programs["handle_cgroup_attach_task"]},
		{name: "cgroup_rmdir", program: coll.Programs["handle_cgroup_rmdir"]},
		{name: "security_file_open", program: coll.Programs["handle_security_file_open"]},
		{name: "security_inode_unlink", program: coll.Programs["handle_security_inode_unlink"]},
		{name: "security_inode_rmdir", program: coll.Programs["handle_security_inode_rmdir"]},
		{name: "security_inode_rename", program: coll.Programs["handle_security_inode_rename"]},
		{name: "security_inode_link", program: coll.Programs["handle_security_inode_link"]},
		{name: "security_inode_symlink", program: coll.Programs["handle_security_inode_symlink"]},
		{name: "udp_sendmsg", program: coll.Programs["handle_udp_sendmsg"]},
		{name: "udpv6_sendmsg", program: coll.Programs["handle_udpv6_sendmsg"]},
		{name: "tcp_sendmsg", program: coll.Programs["handle_tcp_sendmsg"]},
		{name: "unix_stream_sendmsg", program: coll.Programs["handle_unix_stream_sendmsg"]},
		{name: "security_socket_connect", program: coll.Programs["handle_security_socket_connect"]},
	} {
		if attach.program == nil {
			kernelIO.logger.Warn("skipping tracing program pruned at load (not attachable on this kernel)",
				"program", attach.name)
			continue
		}
		attached, err := link.AttachTracing(link.TracingOptions{Program: attach.program})
		if err != nil {
			kernelIO.logger.Warn("skipping tracing program not attachable on this kernel",
				"program", attach.name, "error", err.Error())
			continue
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
		{name: "cgroup/connect4", attachType: ebpf.AttachCGroupInet4Connect, program: coll.Programs["handle_cgroup_connect4"]},
		{name: "cgroup/connect6", attachType: ebpf.AttachCGroupInet6Connect, program: coll.Programs["handle_cgroup_connect6"]},
	} {
		if attach.program == nil {
			kernelIO.logger.Warn("skipping cgroup program pruned at load (not attachable on this kernel)",
				"program", attach.name)
			continue
		}
		attached, err := link.AttachCgroup(link.CgroupOptions{
			Path:    config.CgroupV2RootPath,
			Attach:  attach.attachType,
			Program: attach.program,
		})
		if err != nil {
			kernelIO.logger.Warn("skipping cgroup program not attachable on this kernel",
				"program", attach.name, "error", err.Error())
			continue
		}
		kernelIO.links = append(kernelIO.links, attached)
	}

	// Surface how many probes actually attached so a degraded (custom-kernel)
	// start is visible in the agent log.
	kernelIO.logger.Info("kernel probes attached", "count", len(kernelIO.links))

	reader, err := ringbuf.NewReader(kernelIO.objs.Events)
	if err != nil {
		return nil, fmt.Errorf("open events ringbuf: %w", err)
	}
	kernelIO.reader = reader
	return kernelIO, nil
}

// pruneUnattachableTracingPrograms removes fentry/fexit programs whose target
// kernel function is not exposed for ftrace/fentry on this kernel. cilium/ebpf
// verifies the attach target during BPF_PROG_LOAD, so leaving an unattachable
// fentry program in the spec fails the entire collection load. When
// available_filter_functions cannot be read the spec is left untouched.
func pruneUnattachableTracingPrograms(spec *ebpf.CollectionSpec, logger *slog.Logger) {
	available, err := readAvailableFilterFunctions()
	if err != nil {
		logger.Warn("cannot read available_filter_functions; not pruning tracing programs",
			"error", err.Error())
		return
	}
	for name, programSpec := range spec.Programs {
		if programSpec.Type != ebpf.Tracing {
			continue
		}
		if programSpec.AttachType != ebpf.AttachTraceFEntry && programSpec.AttachType != ebpf.AttachTraceFExit {
			continue
		}
		target := programSpec.AttachTo
		if target == "" || available[target] {
			continue
		}
		logger.Warn("pruning tracing program: attach target not fentry-attachable on this kernel",
			"program", name, "target", target)
		delete(spec.Programs, name)
	}
}

// readAvailableFilterFunctions returns the set of kernel functions that can be
// attached via ftrace/fentry, read from tracefs. Each line is "funcname" or
// "funcname [module]"; only the function name is kept.
func readAvailableFilterFunctions() (map[string]bool, error) {
	for _, path := range []string{
		"/sys/kernel/tracing/available_filter_functions",
		"/sys/kernel/debug/tracing/available_filter_functions",
	} {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		defer file.Close()

		functions := make(map[string]bool)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			name := scanner.Text()
			if space := strings.IndexByte(name, ' '); space >= 0 {
				name = name[:space]
			}
			functions[name] = true
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scan %s: %w", path, err)
		}
		return functions, nil
	}
	return nil, errors.New("available_filter_functions not found under tracefs")
}
