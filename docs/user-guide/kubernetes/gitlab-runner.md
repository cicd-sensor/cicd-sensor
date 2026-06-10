# GitLab Runner Kubernetes executor

GitLab Runner Kubernetes executor support is available as preview support.

Install the shared [Kubernetes runner setup](index.md) first, then configure GitLab Runner with the Kubernetes executor.
cicd-sensor does not require a GitLab-specific hook in this mode.
The node-level cicd-sensor DaemonSet runs privileged as root; GitLab job Pods do not mount host runtime or cicd-sensor staging sockets.

## Runner behavior

| GitLab Runner container | Default handling |
| --- | --- |
| `build` | Monitored. |
| user-defined service containers | Monitored as part of the same CI job. |
| `helper` | Not monitored by default. |
| `init-permissions` | Not monitored by default. |

## Install shape

Install cicd-sensor as a node-level DaemonSet with NRI enabled:

- [`examples/kubernetes/gitlab-runner/kubernetes-executor/daemonset.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/gitlab-runner/kubernetes-executor/daemonset.yaml)

Configure GitLab Runner Kubernetes executor with:

- [`examples/kubernetes/gitlab-runner/kubernetes-executor/values.yaml`](https://github.com/cicd-sensor/cicd-sensor/blob/main/examples/kubernetes/gitlab-runner/kubernetes-executor/values.yaml)

See [Kubernetes runner install](index.md) for shared node requirements.
For implementation details, see [Kubernetes Runtime](../../developer-guide/kubernetes-runtime.md).
