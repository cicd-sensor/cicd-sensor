# GitHub ARC runner scale sets

GitHub Actions support for Actions Runner Controller is in development.
This page describes the planned deployment model for ARC runner scale sets.

Use the official `gha-runner-scale-set` Helm chart.
Install the shared [Kubernetes runner setup](index.md) first, then configure the ARC runner scale set for the mode you use.
The node-level cicd-sensor DaemonSet runs privileged as root; do not mount host runtime or cicd-sensor staging sockets into workflow-created Pods.

## Mode summary

| ARC mode | What runs where | cicd-sensor setup | Notes |
| --- | --- | --- | --- |
| [`containerMode` unset](#default-mode) | The job runs in the runner container. | Job hook + GitHub Kubernetes runner socket. | Best for script, JavaScript action, and composite action workflows. |
| [`containerMode.type: dind`](#dind-mode) | The runner talks to a privileged dind sidecar. | Job hook + GitHub Kubernetes runner socket. | Highest compatibility with Docker workflows, but higher security risk. |
| [`containerMode.type: kubernetes`](#kubernetes-mode) | Job containers, services, and container actions become Kubernetes Pods. | Job hook + GitHub Kubernetes runner socket + container customization hook wrapper + NRI. | Kubernetes-native and avoids dind, but Docker daemon workflows need alternatives. |

## Hook types

GitHub ARC support uses two different GitHub runner hook mechanisms:

| Hook mechanism | GitHub setting | When it runs | cicd-sensor use |
| --- | --- | --- | --- |
| [Job hook](https://docs.github.com/actions/hosting-your-own-runners/managing-self-hosted-runners/running-scripts-before-or-after-a-job) | `ACTIONS_RUNNER_HOOK_JOB_STARTED` | After a job is assigned to the runner and before workflow steps run. | Calls the GitHub Kubernetes runner socket to start monitoring and bind the runner cgroup. |
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
| Node install | [`examples/kubernetes/github-arc/default-mode/daemonset.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/default-mode/daemonset.yaml) |
| Job hook | `ACTIONS_RUNNER_HOOK_JOB_STARTED` in the runner container. |
| Job hook ConfigMap | [`examples/kubernetes/github-arc/common/job-hook-configmap.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/common/job-hook-configmap.yaml) |
| GitHub Kubernetes runner socket | Required in the runner container so the job hook can start monitoring and bind the runner cgroup. |
| NRI | Not used in this mode. |
| ARC values | [`examples/kubernetes/github-arc/default-mode/values.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/default-mode/values.yaml) |

### dind mode

In dind mode, ARC creates a runner container and a privileged dind sidecar in the same Pod.

| Requirement | dind mode |
| --- | --- |
| Node install | [`examples/kubernetes/github-arc/dind-mode/daemonset.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/dind-mode/daemonset.yaml) |
| Job hook | `ACTIONS_RUNNER_HOOK_JOB_STARTED` in the runner container. |
| Job hook ConfigMap | [`examples/kubernetes/github-arc/common/job-hook-configmap.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/common/job-hook-configmap.yaml) |
| GitHub Kubernetes runner socket | Required in the runner container so the job hook can start monitoring and bind the runner plus dind sidecar cgroups. |
| NRI | Not used in this mode. Host NRI does not see inner Docker lifecycle created by dind. |
| ARC values | [`examples/kubernetes/github-arc/dind-mode/values.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/dind-mode/values.yaml) |

dind is a compatibility mode.
It supports existing Docker-heavy workflows, but privileged dind materially increases the risk of host compromise compared with ordinary Kubernetes job containers.

### Kubernetes mode

In Kubernetes mode, ARC uses GitHub's container hooks to create workflow job containers, services, and container actions as Kubernetes Pods.

| Requirement | Kubernetes mode |
| --- | --- |
| Node install | [`examples/kubernetes/github-arc/kubernetes-mode/daemonset.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/kubernetes-mode/daemonset.yaml) |
| Job hook | `ACTIONS_RUNNER_HOOK_JOB_STARTED` in the runner container. |
| Job hook ConfigMap | [`examples/kubernetes/github-arc/common/job-hook-configmap.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/common/job-hook-configmap.yaml) |
| GitHub Kubernetes runner socket | Required in the runner container so the job hook can start monitoring and bind the runner cgroup. |
| Container customization hook wrapper | Required. Use [`examples/kubernetes/github-arc/kubernetes-mode/container-hook-wrapper-configmap.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/kubernetes-mode/container-hook-wrapper-configmap.yaml). |
| NRI | Required. NRI reads injected Pod annotations and runtime cgroup paths for workflow job, service, and container-action Pods. |
| ARC values | [`examples/kubernetes/github-arc/kubernetes-mode/values.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/kubernetes-mode/values.yaml) |

Do not mount cicd-sensor sockets into workflow-created job, service, or step containers.

## Example files

Current Kubernetes examples:

| File | Use |
| --- | --- |
| [`examples/kubernetes/github-arc/default-mode/daemonset.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/default-mode/daemonset.yaml) | Node-level install for ARC default mode. |
| [`examples/kubernetes/github-arc/default-mode/values.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/default-mode/values.yaml) | ARC default mode runner scale set values. |
| [`examples/kubernetes/github-arc/dind-mode/daemonset.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/dind-mode/daemonset.yaml) | Node-level install for ARC dind mode. |
| [`examples/kubernetes/github-arc/dind-mode/values.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/dind-mode/values.yaml) | ARC dind mode runner scale set values. |
| [`examples/kubernetes/github-arc/common/job-hook-configmap.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/common/job-hook-configmap.yaml) | Job hook script used by all ARC modes. |
| [`examples/kubernetes/github-arc/kubernetes-mode/daemonset.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/kubernetes-mode/daemonset.yaml) | Node-level install for ARC Kubernetes mode. |
| [`examples/kubernetes/github-arc/kubernetes-mode/container-hook-wrapper-configmap.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/kubernetes-mode/container-hook-wrapper-configmap.yaml) | ARC Kubernetes mode container customization hook wrapper. |
| [`examples/kubernetes/github-arc/kubernetes-mode/values.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/kubernetes-mode/values.yaml) | ARC Kubernetes mode Helm values snippet. |

For implementation details, see [Kubernetes Runtime](../../developer-guide/kubernetes-runtime.md).
