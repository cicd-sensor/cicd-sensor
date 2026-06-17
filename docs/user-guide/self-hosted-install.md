# Machine runner install

This page covers the host-side setup shared by GitHub Actions self-hosted runners on machines and GitLab Runner Docker executor hosts.

For these machine-based deployments, install the cicd-sensor Agent and Docker proxy on the runner host and operate them with cicd-sensor Manager.
For GitHub Actions-specific hook setup, see [GitHub Actions machine runner](github-self-hosted.md).
For the GitLab Runner Docker executor model, see [GitLab Runner Docker executor](gitlab-ci.md).

## OS / Linux prerequisites

- Linux kernel:
  - `amd64`: 5.15 or later.
  - `arm64`: 6.1 or later. The arm64 lower bound is set by upstream Linux because BPF trampoline / fentry attach landed on arm64 only in 6.0+; on older arm64 kernels the agent fails to attach with `create raw tracepoint: not supported`.
  - Kernel BTF: the running kernel must expose BTF at `/sys/kernel/btf/vmlinux`; the kernel version alone is not sufficient for cicd-sensor's eBPF CO-RE programs. The kernel should be built with `CONFIG_DEBUG_INFO_BTF=y`. Check with:

    ```sh
    ls /sys/kernel/btf/vmlinux
    ```

- cgroup v2.
- systemd.
- dockerd.

## Network requirements

Allow outbound HTTPS from the Agent host to the Manager URL.

| Destination | Purpose |
| --- | --- |
| Manager URL | Fetch config and rules, and send Summary Logs, Detection Logs, and Runtime Event Logs |

When using Manager, the Agent does not connect directly to the public baseline rule registries or the host used to fetch Sigstore root certificates.
The Manager fetches and verifies baseline rules.

## Install path

cicd-sensor releases are available from [cicd-sensor/cicd-sensor releases](https://github.com/cicd-sensor/cicd-sensor/releases).

This guide uses `/opt/cicd-sensor` as the fixed install path for cicd-sensor binaries and hook scripts.

The release tarball ships architecture-suffixed binaries; rename them to the canonical names below so the systemd units resolve them:

```sh
sudo install -d -m 0755 /opt/cicd-sensor
sudo tar -xzf cicd-sensor_<version>_linux_<arch>.tar.gz -C /opt/cicd-sensor
sudo mv /opt/cicd-sensor/cicd-sensor-linux-<arch> /opt/cicd-sensor/cicd-sensor
sudo mv /opt/cicd-sensor/cicd-sensor-manager-linux-<arch> /opt/cicd-sensor/cicd-sensor-manager
sudo mv /opt/cicd-sensor/cicd-sensorctl-linux-<arch> /opt/cicd-sensor/cicd-sensorctl
```

```text
/opt/cicd-sensor/
  cicd-sensor
  cicd-sensor-manager
  cicd-sensorctl
```

## User / root execution model

This guide runs the Agent and Docker proxy as root.

The Agent needs root-equivalent privileges to attach eBPF programs, read cgroup state, and trace process activity.
The Docker proxy and Agent must also run with the same privileges because the proxy uses peer UID checks when calling Agent internal endpoints.

## Manager token

Create the manager token source file under `/etc/cicd-sensor/`.

```sh
sudo install -d -m 0750 /etc/cicd-sensor
echo "MANAGER_TOKEN_HERE" | sudo tee /etc/cicd-sensor/manager-token >/dev/null
sudo chmod 0600 /etc/cicd-sensor/manager-token
sudo chown root:root /etc/cicd-sensor/manager-token
```

For systemd, load it as a service credential:

```ini
[Service]
LoadCredential=manager_token:/etc/cicd-sensor/manager-token
```

systemd copies the source file into a service-specific runtime credential directory and sets `CREDENTIALS_DIRECTORY`.
Pass that runtime copy to cicd-sensor with `--manager-token-file ${CREDENTIALS_DIRECTORY}/manager_token`.
The complete service example below includes both settings.

## Sensor startup

Run the Agent as a systemd service.
Set `--provider` for the target environment.

| Environment | `--provider` | `--runner` |
| --- | --- | --- |
| GitHub Actions self-hosted runner on a machine | `github` | `machine` |
| GitLab Runner Docker executor | `gitlab` | `machine` |

```ini
# /etc/systemd/system/cicd-sensor-agent.service
[Unit]
Description=cicd-sensor Agent
After=network-online.target
Wants=network-online.target
RefuseManualStop=yes
IgnoreOnIsolate=yes

[Service]
Type=simple
RuntimeDirectory=cicd-sensor
RuntimeDirectoryMode=0755
LoadCredential=manager_token:/etc/cicd-sensor/manager-token
ExecStart=/opt/cicd-sensor/cicd-sensor agent start \
  --provider github \
  --runner machine \
  --manager-url https://cicd-sensor-manager.example.com \
  --manager-token-file ${CREDENTIALS_DIRECTORY}/manager_token
Restart=always
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
OOMScoreAdjust=-1000
KillMode=mixed
TimeoutStopSec=5s

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now cicd-sensor-agent.service
```

For GitLab CI/CD, change `--provider github` to `--provider gitlab`.

`RefuseManualStop=yes` rejects manual `systemctl stop`.
Remove it if your maintenance workflow normally uses stop / restart.

## Docker proxy

Machine runner deployments assume dockerd.
Place `cicd-sensor proxy dockerd` in front of the Docker socket so cicd-sensor can observe container creation.

After installation, workflows and runner-side Docker clients still connect to `/run/docker.sock`.
`/run/docker.sock` is served by the cicd-sensor Docker proxy, and the real dockerd socket moves to `/run/docker-upstream.sock`.

```text
docker client
  -> /run/docker.sock                 # cicd-sensor proxy
  -> /run/docker-upstream.sock        # real dockerd
```

Run the Docker proxy as the same user as the Agent, usually root.
If the Agent and proxy run as different users, Agent internal endpoints reject proxy requests.

```ini
# /etc/systemd/system/cicd-sensor-docker-proxy.service
[Unit]
Description=cicd-sensor Docker proxy
After=cicd-sensor-agent.service docker.service
Requires=cicd-sensor-agent.service docker.service

[Service]
Type=simple
Group=docker
UMask=0117
ExecStartPre=/bin/rm -f /run/docker.sock
ExecStart=/opt/cicd-sensor/cicd-sensor proxy dockerd --provider github
Restart=on-failure
RestartSec=100ms

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now cicd-sensor-docker-proxy.service
docker info
```

For GitLab CI/CD, change `--provider github` to `--provider gitlab`.

Docker's systemd socket unit commonly uses `SocketMode=0660` and `SocketGroup=docker`.
Because the cicd-sensor Docker proxy creates `/run/docker.sock` from a service process, this service uses `Group=docker` and `UMask=0117` to produce the same `root:docker` / `0660` access model.
Adjust these settings if your runner host manages Docker socket access differently.

## Dockerd socket setting

dockerd can be installed and managed in several ways.
This example assumes the runner host uses systemd `docker.socket` to manage the Docker socket.

Override the `docker.socket` listen path and move the real dockerd socket to `/run/docker-upstream.sock`.

```ini
# /etc/systemd/system/docker.socket.d/override.conf
[Socket]
ListenStream=
ListenStream=/run/docker-upstream.sock
```

Apply the override.

```sh
sudo systemctl daemon-reload
sudo systemctl restart docker.socket
sudo systemctl restart docker.service
```

Confirm that real dockerd responds on the upstream socket.

```sh
sudo docker -H unix:///run/docker-upstream.sock info
```

## Optional: Linux security hardening

On Linux hosts that use AppArmor or SELinux, add an Agent profile / policy that matches the runner host distribution, policy model, and cicd-sensor features you enable.
