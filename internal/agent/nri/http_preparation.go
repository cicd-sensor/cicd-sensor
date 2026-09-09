package nri

import (
	"context"
	"fmt"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	nriapi "github.com/containerd/nri/pkg/api"
)

type httpPreparer interface {
	Prepare(context.Context, string, []string, kernelio.HTTPPreparationOptions) error
}

// StartContainer prepares the final init root before containerd/CRI task.Start.
// It changes no cgroup attribution and never fails workload startup. The NRI
// observer must run in the node PID/mount view used by the existing deployment.
func (o *Observer) StartContainer(ctx context.Context, pod *nriapi.PodSandbox, container *nriapi.Container) error {
	o.prepareContainerHTTP(ctx, pod, container, "nri-start")
	return nil
}

func (o *Observer) prepareContainerHTTP(ctx context.Context, pod *nriapi.PodSandbox, container *nriapi.Container, source string) {
	if container == nil || container.GetPid() == 0 || o.preparation == nil {
		return
	}
	event := NormalizeCreateContainer(pod, container)
	_, eligible := stagingDecisionForCreateContainer(o.provider, event)
	if !eligible {
		return
	}
	root := fmt.Sprintf("/proc/%d/root", container.GetPid())
	extra := httpprepare.BinDirectories(container.GetArgs(), container.GetEnv())
	if err := o.preparation.Prepare(ctx, root, extra, kernelio.HTTPPreparationOptions{Source: source}); err != nil && o.logger != nil {
		o.logger.WarnContext(ctx, "nri_http_preparation_incomplete", "container_id", container.GetId(), "error", err)
	}
}

// Synchronize can prepare a bounded set of known CI containers after reconnect.
// It does not recreate Jobs or replay missed CreateContainer staging events.
func (o *Observer) Synchronize(ctx context.Context, pods []*nriapi.PodSandbox, containers []*nriapi.Container) ([]*nriapi.ContainerUpdate, error) {
	ctx, cancel := context.WithTimeout(ctx, httpprepare.Budget)
	defer cancel()
	byID := make(map[string]*nriapi.PodSandbox)
	for i, pod := range pods {
		if i >= 4096 {
			break
		}
		if pod != nil {
			byID[pod.GetId()] = pod
		}
	}
	for i, container := range containers {
		if i >= 32 || ctx.Err() != nil {
			break
		}
		if container != nil {
			o.prepareContainerHTTP(ctx, byID[container.GetPodSandboxId()], container, "nri-synchronize")
		}
	}
	return nil, nil
}
