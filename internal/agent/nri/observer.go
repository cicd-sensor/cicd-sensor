// Package nri observes Kubernetes/containerd container creation through NRI.
package nri

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

const (
	// DefaultSocketPath is the well-known external NRI plugin socket.
	DefaultSocketPath = nriapi.DefaultSocketPath

	pluginName  = "cicd-sensor"
	pluginIndex = "90"
)

// Options configures the NRI observer process.
type Options struct {
	SocketPath string
	Logger     *slog.Logger
}

// Observer logs CreateContainer requests and returns no runtime adjustments.
type Observer struct {
	logger *slog.Logger
}

// Run registers the observer with containerd NRI and blocks until ctx ends.
func Run(ctx context.Context, opts Options) error {
	if err := ValidateOptions(opts); err != nil {
		return err
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "nri")

	observer := &Observer{logger: logger}
	nriStub, err := stub.New(observer,
		stub.WithSocketPath(opts.SocketPath),
		stub.WithPluginName(pluginName),
		stub.WithPluginIdx(pluginIndex),
	)
	if err != nil {
		return fmt.Errorf("create nri stub: %w", err)
	}

	logger.InfoContext(ctx, "nri_observer_starting",
		"nri_socket", opts.SocketPath,
		"plugin_name", pluginName,
		"plugin_index", pluginIndex,
	)
	if err := nriStub.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("run nri stub: %w", err)
	}
	return nil
}

// ValidateOptions validates observer process options without starting NRI.
func ValidateOptions(opts Options) error {
	if opts.SocketPath == "" {
		return errors.New("nri socket path is required")
	}
	return nil
}

// CreateContainer is invoked by the NRI stub when containerd sends a ttrpc
// CreateContainer request. It never requests adjustments or updates because
// this prototype is discovery-only.
func (o *Observer) CreateContainer(ctx context.Context, pod *nriapi.PodSandbox, container *nriapi.Container) (*nriapi.ContainerAdjustment, []*nriapi.ContainerUpdate, error) {
	event := NormalizeCreateContainer(pod, container)
	o.logger.InfoContext(ctx, "nri_create_container",
		"pod", event.Pod,
		"container", event.Container,
		"cgroup_basename", event.CgroupBasename,
	)
	return nil, nil, nil
}

// CreateContainerEvent is the raw observer log shape for CreateContainer.
type CreateContainerEvent struct {
	Pod            PodSnapshot       `json:"pod"`
	Container      ContainerSnapshot `json:"container"`
	CgroupBasename string            `json:"cgroup_basename,omitempty"`
}

// PodSnapshot captures the raw Pod fields relevant to the discovery phase.
type PodSnapshot struct {
	ID          string            `json:"id,omitempty"`
	Name        string            `json:"name,omitempty"`
	UID         string            `json:"uid,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	CgroupsPath string            `json:"cgroups_path,omitempty"`
}

// ContainerSnapshot captures the raw container fields relevant to staging.
type ContainerSnapshot struct {
	ID          string            `json:"id,omitempty"`
	Name        string            `json:"name,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Env         []string          `json:"env,omitempty"`
	CgroupsPath string            `json:"cgroups_path,omitempty"`
}

// NormalizeCreateContainer converts NRI API objects into a stable log shape.
func NormalizeCreateContainer(pod *nriapi.PodSandbox, container *nriapi.Container) CreateContainerEvent {
	event := CreateContainerEvent{
		Pod: PodSnapshot{
			ID:          pod.GetId(),
			Name:        pod.GetName(),
			UID:         pod.GetUid(),
			Namespace:   pod.GetNamespace(),
			Labels:      pod.GetLabels(),
			Annotations: pod.GetAnnotations(),
			CgroupsPath: pod.GetLinux().GetCgroupsPath(),
		},
		Container: ContainerSnapshot{
			ID:          container.GetId(),
			Name:        container.GetName(),
			Labels:      container.GetLabels(),
			Annotations: container.GetAnnotations(),
			Env:         container.GetEnv(),
			CgroupsPath: container.GetLinux().GetCgroupsPath(),
		},
	}
	if basename, ok := CgroupBasename(event.Container.CgroupsPath); ok {
		event.CgroupBasename = basename
	}
	return event
}

// CgroupBasename extracts the cgroup_mkdir basename used by staging_map.
// Kubernetes NRI support requires runc systemd cgroups: NRI exposes OCI
// linux.cgroupsPath as [slice]:[prefix]:[name], while BPF matches staging_map
// against cgroup_mkdir's <prefix>-<name>.scope basename. For example:
// kubepods-besteffort-podabc.slice:cri-containerd:857e7bad -> cri-containerd-857e7bad.scope.
// See:
//   - https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#cgroups
//   - https://github.com/opencontainers/runc/blob/main/docs/systemd.md
func CgroupBasename(cgroupsPath string) (string, bool) {
	cgroupsPath = strings.TrimSpace(cgroupsPath)
	if cgroupsPath == "" {
		return "", false
	}

	parts := strings.Split(cgroupsPath, ":")
	if len(parts) != 3 {
		return "", false
	}
	prefix := strings.TrimSpace(parts[1])
	name := strings.TrimSpace(parts[2])
	if prefix == "" || name == "" {
		return "", false
	}
	return prefix + "-" + name + ".scope", true
}
