# GitLab Runner Kubernetes executor

GitLab Runner Kubernetes executor support is available as preview support.
This page is an install guide for GitLab Runner on Kubernetes.
For runtime details such as NRI, cgroups, and GitLab identity extraction, see [Kubernetes Runtime](../../developer-guide/kubernetes-runtime.md).

Use GitLab's official [GitLab Runner Helm chart](https://docs.gitlab.com/runner/install/kubernetes/) with the [Kubernetes executor](https://docs.gitlab.com/runner/executors/kubernetes/).
Review the shared [Kubernetes runner setup](index.md), then install cicd-sensor on the nodes that run GitLab Runner jobs.

## Before you start

1. Install [cicd-sensor Manager](../manager.md) and create a manager token.
2. Confirm the node requirements on [Kubernetes runner install](index.md), including Linux cgroup v2, containerd NRI, and runc systemd cgroups.
3. Install or prepare GitLab Runner using GitLab's [Helm chart](https://docs.gitlab.com/runner/install/kubernetes/) docs.
4. Configure GitLab Runner with the [Kubernetes executor](https://docs.gitlab.com/runner/executors/kubernetes/).
5. Decide the namespace for GitLab Runner. This guide uses `gitlab-runner`.

Use the current GitLab Runner authentication token flow and store the runner token in a Kubernetes Secret.
Do not commit runner tokens or manager tokens into values files.

Use pinned cicd-sensor image tags and pinned GitLab Runner chart versions in production.
The example files use `:latest` only as a placeholder.

## Security and operational notes

- The cicd-sensor DaemonSet is a privileged node agent.
- GitLab Runner Kubernetes executor does not need a GitLab-specific hook.
- GitLab job Pods do not mount host `containerd.sock`, CRI socket, NRI socket, or `/run/cicd-sensor` internal sockets.
- cicd-sensor reads GitLab Runner-created Pod labels and annotations from host-side NRI events.

## Install

Create the cicd-sensor namespace and the GitLab Runner namespace:

```sh
kubectl create namespace cicd-sensor-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace gitlab-runner --dry-run=client -o yaml | kubectl apply -f -
```

Create the manager token secret from your shell environment instead of writing the token into a manifest file:

```sh
kubectl -n cicd-sensor-system create secret generic cicd-sensor-manager \
  --from-literal=token="${CICD_SENSOR_MANAGER_TOKEN}" \
  --dry-run=client -o yaml | kubectl apply -f -
```

Copy these files into your environment-specific install directory:

| Local file | Copy from |
| --- | --- |
| `cicd-sensor-daemonset.yaml` | [`examples/kubernetes/gitlab-runner/kubernetes-executor/daemonset.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/gitlab-runner/kubernetes-executor/daemonset.yaml) |
| `gitlab-runner-values.yaml` | merge [`examples/kubernetes/gitlab-runner/kubernetes-executor/values.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/gitlab-runner/kubernetes-executor/values.yaml) into your existing GitLab Runner values |

Edit `cicd-sensor-daemonset.yaml`:

- set `CICD_SENSOR_MANAGER_URL`
- set namespace names if you do not use `cicd-sensor-system`
- pin the cicd-sensor image tag
- confirm the `cicd-sensor-manager` secret name matches the secret you created

Merge the GitLab Runner values into your existing Helm values.
The example is only a minimal Kubernetes executor snippet.
Keep your existing `gitlabUrl`, runner registration, tags, cache, and resource settings.
If you expect concurrent jobs, review the GitLab Runner `request_concurrency` setting as well; a low value can make Kubernetes runner verification look serialized even when the cluster has capacity.

Apply cicd-sensor:

```sh
kubectl apply -f cicd-sensor-daemonset.yaml
```

Install or upgrade GitLab Runner with your merged values:

```sh
helm repo add gitlab https://charts.gitlab.io
helm repo update

helm upgrade --install gitlab-runner gitlab/gitlab-runner \
  --namespace gitlab-runner \
  --version GITLAB_RUNNER_CHART_VERSION \
  --values gitlab-runner-values.yaml
```

## Verify

Check the cicd-sensor DaemonSet:

```sh
kubectl -n cicd-sensor-system rollout status daemonset/cicd-sensor
kubectl -n cicd-sensor-system logs daemonset/cicd-sensor -c agent
kubectl -n cicd-sensor-system logs daemonset/cicd-sensor -c nri
```

Expected logs:

| Container | Log signal |
| --- | --- |
| `nri` | `nri_observer_starting` when the NRI observer registers |
| `nri` | `nri_staging_put` when GitLab build or service containers are staged |

Run a GitLab pipeline on the Kubernetes runner.
If the project also has shared runners enabled, use a runner tag or disable shared runners for the verification job so the job is guaranteed to run on this Kubernetes runner.
The job should appear in cicd-sensor Manager logs.

## Uninstall

1. Remove the cicd-sensor DaemonSet.
2. Remove the manager token secret if it is no longer used.
3. Uninstall GitLab Runner only if this cluster no longer needs it.

```sh
kubectl -n cicd-sensor-system delete secret cicd-sensor-manager --ignore-not-found
kubectl -n cicd-sensor-system delete daemonset cicd-sensor --ignore-not-found
kubectl -n cicd-sensor-system delete serviceaccount cicd-sensor --ignore-not-found
```
