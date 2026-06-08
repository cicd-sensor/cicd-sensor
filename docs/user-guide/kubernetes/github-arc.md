# GitHub ARC runner scale sets

GitHub Actions support for Actions Runner Controller is in development.
This page describes the planned deployment model for ARC runner scale sets.

Use the official `gha-runner-scale-set` Helm chart.
Install the shared [Kubernetes runner setup](index.md) first, then configure the ARC runner scale set for the mode you use.

## Mode summary

| ARC mode | What runs where | cicd-sensor setup | Notes |
| --- | --- | --- | --- |
| [`containerMode` unset](#default-mode) | The job runs in the runner container. | Job hook + GitHub k8s start socket. | Best for script, JavaScript action, and composite action workflows. |
| [`containerMode.type: dind`](#dind-mode) | The runner talks to a privileged dind sidecar. | Job hook + GitHub k8s start socket. | Highest compatibility with Docker workflows, but higher security risk. |
| [`containerMode.type: kubernetes`](#kubernetes-mode) | Job containers, services, and container actions become Kubernetes Pods. | Job hook + GitHub k8s start socket + container customization hook wrapper. | Kubernetes-native and avoids dind, but Docker daemon workflows need alternatives. |

## Hook types

GitHub ARC support uses two different GitHub runner hook mechanisms:

| Hook mechanism | GitHub setting | When it runs | cicd-sensor use |
| --- | --- | --- | --- |
| [Job hook](https://docs.github.com/actions/hosting-your-own-runners/managing-self-hosted-runners/running-scripts-before-or-after-a-job) | `ACTIONS_RUNNER_HOOK_JOB_STARTED` | After a job is assigned to the runner and before workflow steps run. | Calls the GitHub k8s start socket to start monitoring and bind the runner cgroup. |
| [Container customization hook wrapper](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/customize-containers) | `ACTIONS_RUNNER_CONTAINER_HOOKS` | During GitHub's container customization flow, such as `prepare_job` and `run_container_step`. | Kubernetes mode only: injects GitHub identity into Pod annotations before ARC creates workflow job, service, and container-action Pods. |

The job hook is the job lifecycle hook.
The container customization hook wrapper is a wrapper around ARC's Kubernetes container hook implementation.
The ConfigMap exists only to distribute that wrapper, so it is only needed in Kubernetes mode.

For ARC runner scale set and Kubernetes-mode hook extension details, see GitHub's [Deploying runner scale sets with Actions Runner Controller](https://docs.github.com/en/enterprise-cloud@latest/actions/tutorials/use-actions-runner-controller/deploy-runner-scale-sets) documentation.

## Deploy by mode

### Default mode

When `containerMode` is not set, ARC creates the runner Pod and the GitHub job runs inside the runner container.
The runner Pod is created before GitHub assigns a job, so NRI cannot build the job identity from the runner container creation event.

| Requirement | Default mode |
| --- | --- |
| Shared node install | `examples/kubernetes/cicd-sensor-daemonset.yaml` |
| Job hook | `ACTIONS_RUNNER_HOOK_JOB_STARTED` in the runner container. |
| GitHub k8s start socket | Required in the runner container so the job hook can start monitoring and bind the runner cgroup. |
| NRI | Required as part of the shared DaemonSet, but not used to identify the GitHub job in this mode. |

### dind mode

In dind mode, ARC creates a runner container and a privileged dind sidecar in the same Pod.

| Requirement | dind mode |
| --- | --- |
| Shared node install | `examples/kubernetes/cicd-sensor-daemonset.yaml` |
| Job hook | `ACTIONS_RUNNER_HOOK_JOB_STARTED` in the runner container. |
| GitHub k8s start socket | Required in the runner container so the job hook can start monitoring and bind the runner plus dind sidecar cgroups. |
| NRI | Required as part of the shared DaemonSet, but host NRI does not see inner Docker lifecycle created by dind. |

dind is a compatibility mode.
It supports existing Docker-heavy workflows, but privileged dind materially increases the risk of host compromise compared with ordinary Kubernetes job containers.

### Kubernetes mode

In Kubernetes mode, ARC uses GitHub's container hooks to create workflow job containers, services, and container actions as Kubernetes Pods.

| Requirement | Kubernetes mode |
| --- | --- |
| Shared node install | `examples/kubernetes/cicd-sensor-daemonset.yaml` |
| Job hook | `ACTIONS_RUNNER_HOOK_JOB_STARTED` in the runner container. |
| GitHub k8s start socket | Required in the runner container so the job hook can start monitoring and bind the runner cgroup. |
| Container customization hook wrapper | Required. Use `examples/kubernetes/github-arc-hook-wrapper-configmap.yaml` and `examples/kubernetes/github-arc-kubernetes-mode-values.yaml`. |
| NRI | Required. NRI reads injected Pod annotations and runtime cgroup paths for workflow job, service, and container-action Pods. |

Do not mount cicd-sensor sockets into workflow-created job, service, or step containers.

## Example files

Current Kubernetes examples:

| File | Use |
| --- | --- |
| `examples/kubernetes/cicd-sensor-daemonset.yaml` | Shared node-level install for all ARC modes. |
| `examples/kubernetes/github-arc-hook-wrapper-configmap.yaml` | ARC Kubernetes mode container customization hook wrapper. |
| `examples/kubernetes/github-arc-kubernetes-mode-values.yaml` | ARC Kubernetes mode Helm values snippet. |

The job hook and GitHub k8s start socket values are required for all ARC modes.
Those example values are still to be added.

For implementation details, see [Kubernetes Runtime](../../developer-guide/kubernetes-runtime.md).
