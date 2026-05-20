# Self-hosted Machine install

This page covers the host-side setup shared by GitHub Actions Self-hosted Machine Runners and GitLab CI/CD Self-hosted Container Executors.

In self-hosted deployments, install the cicd-sensor Agent and Docker proxy on the runner host and operate them with cicd-sensor Manager.
For GitHub Actions-specific hook setup, see [GitHub Actions self-hosted](github-self-hosted.md).
For the GitLab CI/CD runner model, see [GitLab CI/CD self-hosted](gitlab-ci.md).

## OS / Linux prerequisites

- Linux kernel 5.15+.
- cgroup v2.
- systemd.
- dockerd.

## Install path

cicd-sensor releases are available from [cicd-sensor/cicd-sensor releases](https://github.com/cicd-sensor/cicd-sensor/releases).

This guide uses `/opt/cicd-sensor` as the fixed install path.
The systemd units, hook scripts, and manager token examples all assume this path.

```text
/opt/cicd-sensor/
  cicd-sensor
  cicd-sensor-manager
  cicd-sensorctl
  manager-token
```

## User / root execution model

Do not create a dedicated non-root Linux user for cicd-sensor.
Run the Agent and Docker proxy as the same user, usually root.

Reasons:

- The Agent needs access to eBPF, cgroup, and process telemetry.
- The Docker proxy uses peer UID checks when connecting to Agent internal endpoints.
- The Agent socket must be reachable by any user on the runner host.

The socket file's Unix permissions are not used to restrict which users can connect.
For endpoints that require authorization, the Agent validates the request using the peer UID / PID and cgroup context.

## Manager token

Do not write the manager token into a config file.
Use one of these two methods.

| Method | How to set it | Notes |
| --- | --- | --- |
| Environment variable | `CICD_SENSOR_MANAGER_TOKEN=...` | Useful with systemd `EnvironmentFile=` or secret-manager integration |
| Token file | `--manager-token-file /path/to/token` | Does not expose the token value on the command line. Recommended for systemd units. |

When using a token file:

```sh
sudo install -d -m 0755 /opt/cicd-sensor
sudo sh -c 'printf "%s\n" "sk_cs_..." > /opt/cicd-sensor/manager-token'
sudo chmod 0600 /opt/cicd-sensor/manager-token
```

When using an environment variable:

```ini
[Service]
EnvironmentFile=/opt/cicd-sensor/agent.env
```

## Sensor startup

Run the Agent as a systemd service.
Set `--provider` for the target environment.

| Environment | `--provider` | `--runner` |
| --- | --- | --- |
| GitHub Actions Self-hosted Machine Runner | `github` | `machine` |
| GitLab CI/CD Self-hosted Container Executor | `gitlab` | `machine` |

```ini
# /etc/systemd/system/cicd-sensor-agent.service
[Unit]
Description=cicd-sensor Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
UMask=0000
RuntimeDirectory=cicd-sensor
RuntimeDirectoryMode=0755
ExecStart=/opt/cicd-sensor/cicd-sensor agent start \
  --provider github \
  --runner machine \
  --manager-url https://cicd-sensor-manager.example.com \
  --manager-token-file /opt/cicd-sensor/manager-token
Restart=always
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
RefuseManualStop=yes
IgnoreOnIsolate=yes
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

Additional sandboxing such as `ProtectSystem=strict`, `ProtectProc=...`, `CapabilityBoundingSet=...`, or `SystemCallFilter=...` may break eBPF loading, cgroup access, or process / network / file telemetry.
Enable additional hardening only after validating it with real runner workloads.

## Docker proxy

Self-hosted Machine Runners assume dockerd.
Place `cicd-sensor proxy dockerd` in front of the Docker socket so cicd-sensor can observe container creation.

After installation, workflows and runner-side Docker clients still connect to `/run/docker.sock`.
`/run/docker.sock` is served by the cicd-sensor Docker proxy, and the real dockerd socket moves to `/run/docker-upstream.sock`.

```text
docker client
  -> /run/docker.sock                 # cicd-sensor proxy
  -> /run/docker-upstream.sock        # real dockerd
```

Run the Docker proxy as the same user as the Agent, usually root.
If the Agent and proxy run as different users, internal requests may be rejected.

```ini
# /etc/systemd/system/cicd-sensor-docker-proxy.service
[Unit]
Description=cicd-sensor Docker proxy
After=cicd-sensor-agent.service docker.service
Requires=cicd-sensor-agent.service docker.service

[Service]
Type=simple
Group=docker
UMask=0007
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
