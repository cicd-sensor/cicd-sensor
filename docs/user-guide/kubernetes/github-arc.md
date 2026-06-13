# GitHub ARC runner scale sets

GitHub Actions support for Actions Runner Controller is available as preview support.
This page is an install guide for ARC runner scale sets.
For runtime details such as NRI, cgroups, and hook behavior, see [Kubernetes Runtime](../../developer-guide/kubernetes-runtime.md).

Use GitHub's official [`gha-runner-scale-set` Helm chart](https://docs.github.com/en/actions/how-tos/manage-runners/use-actions-runner-controller/deploy-runner-scale-sets).
Review the shared [Kubernetes runner setup](index.md), then install the mode that matches your ARC runner scale set.

## Choose a mode

| ARC mode | Use when | cicd-sensor setup |
| --- | --- | --- |
| [Default mode](#default-mode) | `containerMode` is not set. Jobs run in the runner container. | DaemonSet + GitHub job hook + runner socket mount. |
| [dind mode](#dind-mode) | Workflows need Docker compatibility, such as `docker build` or Docker Compose. | DaemonSet + GitHub job hook + runner socket mount. |
| [Kubernetes mode](#kubernetes-mode) | Workflow `container:`, `services:`, and container actions should run as Kubernetes Pods. | DaemonSet + NRI + GitHub job hook + ARC container hook wrapper. |

## Before you start

1. Install [cicd-sensor Manager](../manager.md) and create a manager token.
2. Confirm the node requirements on [Kubernetes runner install](index.md), including Linux cgroup v2, containerd NRI, and runc systemd cgroups.
3. Install and authenticate ARC using GitHub's [Actions Runner Controller](https://docs.github.com/en/actions/concepts/runners/actions-runner-controller), [authentication](https://docs.github.com/en/actions/how-tos/manage-runners/use-actions-runner-controller/authenticate-to-the-api), and [runner scale set deployment](https://docs.github.com/en/actions/how-tos/manage-runners/use-actions-runner-controller/deploy-runner-scale-sets) docs.
4. Decide the namespace for your runner scale set. This guide uses `arc-runners`.
5. Set GitHub workflow `runs-on` to your ARC runner scale set name, as described in GitHub's [Using ARC runners in a workflow](https://docs.github.com/en/actions/how-tos/manage-runners/use-actions-runner-controller/use-arc-in-a-workflow) docs.

Use pinned cicd-sensor image tags and pinned ARC chart versions in production.
The example files use `:latest` only as a placeholder.

## Security and operational notes

- The cicd-sensor DaemonSet is a privileged node agent.
- The GitHub job hook is fail-closed. If the agent or GitHub Kubernetes runner socket is unavailable on a node, jobs scheduled on that node can fail before workflow steps run.
- Do not mount host `containerd.sock`, CRI socket, NRI socket, or `/run/cicd-sensor` internal sockets into workflow-created job, service, or step Pods.
- The GitHub Kubernetes runner socket mounted into ARC runner containers is the only cicd-sensor socket exception in this guide.
- The ARC runner namespace must allow the hostPath volume used for the GitHub Kubernetes runner socket.
- dind mode runs a privileged Docker daemon sidecar and should be treated as a higher-risk compatibility mode.
- Kubernetes mode uses `ACTIONS_RUNNER_CONTAINER_HOOKS`; the example wrapper currently overwrites any existing `ACTIONS_RUNNER_CONTAINER_HOOK_TEMPLATE` setting.

## Shared setup

Create the cicd-sensor namespace and the ARC runner namespace before applying ConfigMaps or installing the runner scale set.
The job hook ConfigMap is namespaced, so it must exist before ARC creates runner Pods that reference it.

```sh
kubectl create namespace cicd-sensor-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace arc-runners --dry-run=client -o yaml | kubectl apply -f -
```

If your cluster enforces Pod Security Admission or another admission policy, make sure `arc-runners` allows the hostPath volume used by the runner socket mount.

Create the manager token secret from your shell environment instead of writing the token into a manifest file:

```sh
kubectl -n cicd-sensor-system create secret generic cicd-sensor-manager \
  --from-literal=token="${CICD_SENSOR_MANAGER_TOKEN}" \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Values merge rule

Do not pass your existing ARC values and the cicd-sensor example as two separate `--values` files.
Helm deep-merges maps, but lists are replaced by the later file.
The ARC runner container, `env`, `volumeMounts`, and `volumes` are lists, so a second values file can silently remove either your existing runner settings or the cicd-sensor hook settings.

For each mode below, copy the example values and merge the listed entries into your existing ARC runner scale set values.
Save the merged result as `cicd-sensor-arc-values.yaml`, then pass only that one values file to Helm.

## Default mode

Use this when `containerMode` is not set.
Jobs run directly in the ARC runner container.
This mode is suitable for script, JavaScript action, and composite action workflows.

Copy these files:

| Local file | Copy from |
| --- | --- |
| `cicd-sensor-daemonset.yaml` | [`examples/kubernetes/github-arc/default-mode/daemonset.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/default-mode/daemonset.yaml) |
| `cicd-sensor-job-hook.yaml` | [`examples/kubernetes/github-arc/common/job-hook-configmap.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/common/job-hook-configmap.yaml) |
| `cicd-sensor-arc-values.yaml` | merge [`examples/kubernetes/github-arc/default-mode/values.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/default-mode/values.yaml) into your existing ARC values |

Edit `cicd-sensor-daemonset.yaml`:

- set `CICD_SENSOR_MANAGER_URL`
- set namespace names if you do not use `cicd-sensor-system`
- pin the cicd-sensor image tag
- confirm the `cicd-sensor-manager` secret name matches the secret you created

Merge these values into your existing runner container definition:

- `ACTIONS_RUNNER_HOOK_JOB_STARTED`
- `CICD_SENSOR_GITHUB_K8S_RUNNER_SOCKET`
- the job hook ConfigMap volume and mount
- the GitHub Kubernetes runner socket hostPath volume and mount

Apply and upgrade:

```sh
kubectl apply -f cicd-sensor-daemonset.yaml
kubectl apply -f cicd-sensor-job-hook.yaml

helm upgrade --install RUNNER_SCALE_SET_NAME \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --namespace arc-runners \
  --version ARC_CHART_VERSION \
  --values cicd-sensor-arc-values.yaml
```

## dind mode

Use this when workflows need Docker compatibility, such as `docker build` or Docker Compose.
This mode uses ARC `containerMode.type: dind`.

Copy these files:

| Local file | Copy from |
| --- | --- |
| `cicd-sensor-daemonset.yaml` | [`examples/kubernetes/github-arc/dind-mode/daemonset.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/dind-mode/daemonset.yaml) |
| `cicd-sensor-job-hook.yaml` | [`examples/kubernetes/github-arc/common/job-hook-configmap.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/common/job-hook-configmap.yaml) |
| `cicd-sensor-arc-values.yaml` | merge [`examples/kubernetes/github-arc/dind-mode/values.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/dind-mode/values.yaml) into your existing ARC values |

Edit `cicd-sensor-daemonset.yaml`:

- set `CICD_SENSOR_MANAGER_URL`
- set namespace names if you do not use `cicd-sensor-system`
- pin the cicd-sensor image tag
- confirm the `cicd-sensor-manager` secret name matches the secret you created

Merge these values into your existing runner scale set values:

- `containerMode.type: dind`
- `ACTIONS_RUNNER_HOOK_JOB_STARTED`
- `CICD_SENSOR_GITHUB_K8S_RUNNER_SOCKET`
- the job hook ConfigMap volume and mount
- the GitHub Kubernetes runner socket hostPath volume and mount

Apply and upgrade:

```sh
kubectl apply -f cicd-sensor-daemonset.yaml
kubectl apply -f cicd-sensor-job-hook.yaml

helm upgrade --install RUNNER_SCALE_SET_NAME \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --namespace arc-runners \
  --version ARC_CHART_VERSION \
  --values cicd-sensor-arc-values.yaml
```

## Kubernetes mode

Use this when ARC should create workflow job containers, services, and container actions as Kubernetes Pods.
This mode uses ARC `containerMode.type: kubernetes`.
The workflow-created Pods are pinned to the runner's node so the same node-level agent can handle both job start and NRI staging.
Size runner nodes for the combined runner, workflow, service, and container-action workload.

Copy these files:

| Local file | Copy from |
| --- | --- |
| `cicd-sensor-daemonset.yaml` | [`examples/kubernetes/github-arc/kubernetes-mode/daemonset.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/kubernetes-mode/daemonset.yaml) |
| `cicd-sensor-job-hook.yaml` | [`examples/kubernetes/github-arc/common/job-hook-configmap.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/common/job-hook-configmap.yaml) |
| `cicd-sensor-container-hook-wrapper.yaml` | [`examples/kubernetes/github-arc/kubernetes-mode/container-hook-wrapper-configmap.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/kubernetes-mode/container-hook-wrapper-configmap.yaml) |
| `cicd-sensor-arc-values.yaml` | merge [`examples/kubernetes/github-arc/kubernetes-mode/values.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/github-arc/kubernetes-mode/values.yaml) into your existing ARC values |

Edit `cicd-sensor-daemonset.yaml`:

- set `CICD_SENSOR_MANAGER_URL`
- set namespace names if you do not use `cicd-sensor-system`
- pin the cicd-sensor image tag
- confirm the `cicd-sensor-manager` secret name matches the secret you created

Merge these values into your existing runner scale set values:

- `containerMode.type: kubernetes`
- `kubernetesModeWorkVolumeClaim`
- `template.spec.securityContext.fsGroup: 1001`
- `ACTIONS_RUNNER_HOOK_JOB_STARTED`
- `CICD_SENSOR_GITHUB_K8S_RUNNER_SOCKET`
- `ACTIONS_RUNNER_CONTAINER_HOOKS`
- `CICD_SENSOR_K8S_NODE_NAME`
- the job hook ConfigMap volume and mount
- the GitHub Kubernetes runner socket hostPath volume and mount
- the container hook wrapper ConfigMap volume and mount

The Kubernetes mode example sets `fsGroup: 1001` because ARC shares the work volume between the runner and workflow Pods.
This keeps `/home/runner/_work` and `_tool` writable by the official runner image's runner group.
If your custom runner image uses a different runner GID, adjust `fsGroup` to match it.

Apply and upgrade:

```sh
kubectl apply -f cicd-sensor-daemonset.yaml
kubectl apply -f cicd-sensor-job-hook.yaml
kubectl apply -f cicd-sensor-container-hook-wrapper.yaml

helm upgrade --install RUNNER_SCALE_SET_NAME \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --namespace arc-runners \
  --version ARC_CHART_VERSION \
  --values cicd-sensor-arc-values.yaml
```

## Verify

Check the cicd-sensor DaemonSet:

```sh
kubectl -n cicd-sensor-system rollout status daemonset/cicd-sensor
kubectl -n cicd-sensor-system logs daemonset/cicd-sensor -c agent
```

For Kubernetes mode, also check the NRI container:

```sh
kubectl -n cicd-sensor-system logs daemonset/cicd-sensor -c nri
```

Expected logs:

| Mode | Log signal |
| --- | --- |
| all modes | `github_k8s_start_accepted` after a GitHub job starts |
| Kubernetes mode | `nri_observer_starting` when the NRI observer registers |
| Kubernetes mode | `nri_staging_put` when workflow-created Pods are staged |

Check that ARC runner Pods include the job hook and runner socket mount:

```sh
kubectl -n arc-runners describe pod RUNNER_POD_NAME
```

Look for `ACTIONS_RUNNER_HOOK_JOB_STARTED` and the `/run/cicd-sensor/github-k8s` volume mount.
Then run a GitHub Actions workflow whose `runs-on` matches the runner scale set name.
The job should appear in cicd-sensor Manager logs.

## Uninstall

1. Remove the cicd-sensor env, volume mounts, and volumes from your ARC values, then run `helm upgrade` for the runner scale set.
2. Delete the hook ConfigMaps you applied.
3. Delete the cicd-sensor DaemonSet, ServiceAccount, and manager token secret.

```sh
kubectl -n arc-runners delete configmap cicd-sensor-github-arc-job-hook --ignore-not-found
kubectl -n arc-runners delete configmap cicd-sensor-github-arc-kubernetes-mode-hook-wrapper --ignore-not-found
kubectl -n cicd-sensor-system delete secret cicd-sensor-manager --ignore-not-found
kubectl -n cicd-sensor-system delete daemonset cicd-sensor --ignore-not-found
kubectl -n cicd-sensor-system delete serviceaccount cicd-sensor --ignore-not-found
```
