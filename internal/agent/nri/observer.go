// Package nri observes Kubernetes/containerd container creation through NRI.
package nri

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

const (
	// DefaultSocketPath is the well-known external NRI plugin socket.
	DefaultSocketPath = nriapi.DefaultSocketPath

	pluginName  = "cicd-sensor"
	pluginIndex = "90"

	// Reconnect backoff bounds for lost NRI connections. containerd closes
	// plugin connections on restart and NRI has no event replay, so exiting
	// instead of reconnecting would widen the unobserved-container gap to the
	// DaemonSet restart (plus crash-loop backoff).
	reconnectInitialDelay = time.Second
	reconnectMaxDelay     = 30 * time.Second
	// reconnectResetAfter resets the backoff once a connection has stayed up
	// long enough to count as healthy rather than flapping.
	reconnectResetAfter = time.Minute
)

// Options configures the NRI observer process.
type Options struct {
	SocketPath      string
	AgentSocketPath string
	Provider        jobcontext.Provider
	Logger          *slog.Logger
}

// Observer logs CreateContainer requests, stages known CI/CD containers, and
// returns no runtime adjustments.
type Observer struct {
	logger   *slog.Logger
	agent    *agentClient
	provider jobcontext.Provider
}

// Run registers the observer with containerd NRI and blocks until ctx ends.
// A lost NRI connection (typically a containerd restart) is retried with
// backoff instead of returned: NRI has no event replay and the staging model
// cannot backfill, so containers created while disconnected are permanently
// unobserved — every reconnect log line marks such a monitoring gap.
func Run(ctx context.Context, opts Options) error {
	if err := ValidateOptions(opts); err != nil {
		return err
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "nri")

	observer := &Observer{
		logger:   logger,
		agent:    &agentClient{socketPath: opts.AgentSocketPath},
		provider: opts.Provider,
	}

	delay := reconnectInitialDelay
	for {
		connectedAt := time.Now()
		started, err := runStubOnce(ctx, opts, observer, logger)
		if ctx.Err() != nil {
			return nil
		}
		if !started {
			return err
		}
		if err == nil {
			err = errors.New("nri connection closed")
		}
		if time.Since(connectedAt) >= reconnectResetAfter {
			delay = reconnectInitialDelay
		}
		logger.WarnContext(ctx, "nri_connection_lost",
			"error", err,
			"retry_delay", delay.String(),
			"note", "containers created while disconnected are not staged",
		)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		delay = min(delay*2, reconnectMaxDelay)
	}
}

// runStubOnce serves one NRI connection until it is closed or ctx ends.
// Startup errors are returned with started=false so misconfiguration fails
// loudly; only a connection that was successfully started is eligible for
// reconnect.
func runStubOnce(ctx context.Context, opts Options, observer *Observer, logger *slog.Logger) (started bool, err error) {
	nriStub, err := stub.New(observer,
		stub.WithSocketPath(opts.SocketPath),
		stub.WithPluginName(pluginName),
		stub.WithPluginIdx(pluginIndex),
	)
	if err != nil {
		return false, fmt.Errorf("create nri stub: %w", err)
	}

	logger.InfoContext(ctx, "nri_observer_starting",
		"nri_socket", opts.SocketPath,
		"agent_socket", opts.AgentSocketPath,
		"provider", opts.Provider,
		"plugin_name", pluginName,
		"plugin_index", pluginIndex,
	)
	if err := nriStub.Start(ctx); err != nil {
		return false, fmt.Errorf("start nri stub: %w", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		nriStub.Wait()
	}()

	select {
	case <-done:
		return true, nil
	case <-ctx.Done():
		nriStub.Stop()
		<-done
		return true, ctx.Err()
	}
}

// ValidateOptions validates observer process options without starting NRI.
func ValidateOptions(opts Options) error {
	if opts.SocketPath == "" {
		return errors.New("nri socket path is required")
	}
	if opts.AgentSocketPath == "" {
		return errors.New("agent socket path is required")
	}
	if opts.Provider != jobcontext.ProviderGitHub && opts.Provider != jobcontext.ProviderGitLab {
		return errors.New("nri provider must be github or gitlab")
	}
	return nil
}

// CreateContainer is invoked by the NRI stub when containerd sends a ttrpc
// CreateContainer request. It stages matching CI/CD containers through the
// agent socket but never requests runtime adjustments or updates.
func (o *Observer) CreateContainer(ctx context.Context, pod *nriapi.PodSandbox, container *nriapi.Container) (*nriapi.ContainerAdjustment, []*nriapi.ContainerUpdate, error) {
	event := NormalizeCreateContainer(pod, container)
	decision, shouldStage := stagingDecisionForCreateContainer(o.provider, event)
	o.logger.InfoContext(ctx, "nri_create_container",
		"pod", safePodSnapshotForLog(event.Pod),
		"container", safeContainerSnapshotForLog(event.Container),
		"cgroup_basename", event.CgroupBasename,
		"provider", decision.Provider,
		"identity_status", decision.Status,
		"skip_reason", decision.SkipReason,
	)
	if shouldStage && o.agent != nil {
		stageCtx, cancel := context.WithTimeout(ctx, agentPostTimeout)
		defer cancel()
		if err := o.agent.stage(stageCtx, decision); err != nil {
			o.logger.WarnContext(ctx, "nri_staging_failed",
				"provider", decision.Provider,
				"job_identity", decision.Identity,
				"basename", decision.Basename,
				"error", err,
			)
		} else {
			o.logger.InfoContext(ctx, "nri_staging_put",
				"provider", decision.Provider,
				"job_identity", decision.Identity,
				"basename", decision.Basename,
			)
		}
	}
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

type podLogSnapshot struct {
	ID             string   `json:"id,omitempty"`
	Name           string   `json:"name,omitempty"`
	UID            string   `json:"uid,omitempty"`
	Namespace      string   `json:"namespace,omitempty"`
	LabelKeys      []string `json:"label_keys,omitempty"`
	AnnotationKeys []string `json:"annotation_keys,omitempty"`
	CgroupsPath    string   `json:"cgroups_path,omitempty"`
}

type containerLogSnapshot struct {
	ID             string   `json:"id,omitempty"`
	Name           string   `json:"name,omitempty"`
	LabelKeys      []string `json:"label_keys,omitempty"`
	AnnotationKeys []string `json:"annotation_keys,omitempty"`
	EnvKeys        []string `json:"env_keys,omitempty"`
	CgroupsPath    string   `json:"cgroups_path,omitempty"`
}

func safePodSnapshotForLog(pod PodSnapshot) podLogSnapshot {
	return podLogSnapshot{
		ID:             pod.ID,
		Name:           pod.Name,
		UID:            pod.UID,
		Namespace:      pod.Namespace,
		LabelKeys:      sortedMapKeys(pod.Labels),
		AnnotationKeys: sortedMapKeys(pod.Annotations),
		CgroupsPath:    pod.CgroupsPath,
	}
}

func safeContainerSnapshotForLog(container ContainerSnapshot) containerLogSnapshot {
	return containerLogSnapshot{
		ID:             container.ID,
		Name:           container.Name,
		LabelKeys:      sortedMapKeys(container.Labels),
		AnnotationKeys: sortedMapKeys(container.Annotations),
		EnvKeys:        sortedEnvKeys(container.Env),
		CgroupsPath:    container.CgroupsPath,
	}
}

func sortedMapKeys(values map[string]string) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func sortedEnvKeys(env []string) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	seen := make(map[string]struct{}, len(env))
	for _, kv := range env {
		key, _, ok := strings.Cut(kv, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
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
