# Event types

An event type determines which runtime event a rule evaluates.
Every event type can use `process`.

```yaml
rule_sets:
  - ruleset_id: acme/process
    rules:
      - rule_id: network_tool_exec
        event_type: process_exec
        condition: |
          process.exec_path.endsWith("/curl") ||
          process.exec_path.endsWith("/wget")
        action: collect
```

`process` is the snapshot of the process that produced the event.

| field | Type | Example value | Meaning |
| --- | --- | --- | --- |
| `process.exec_path` | string | `/usr/bin/curl` | Executable path |
| `process.argv` | list(string) | `["curl", "-fsSL", "https://example.com/install.sh"]` | Process arguments |
| `process.ancestors` | list(object) | `[{exec_path: "/bin/bash", argv: ["bash", "-c", "npm install"]}]` | Snapshot of ancestor processes |

`process.ancestors` is newest-first.
The first element is the immediate parent, followed by the grandparent.
Rule conditions should search ancestors with `exists` instead of index access.
Each ancestor exposes `exec_path` and `argv`.

```yaml
condition: |
  process.ancestors.exists(parent,
    parent.exec_path.endsWith("/bash") &&
    parent.argv.exists(arg, arg == "-c")
  )
```

## `process_exec`

Evaluates process execution.

| field | Type | Example value | Meaning |
| --- | --- | --- | --- |
| `process` | object | `process.exec_path == "/usr/bin/curl"` | Executed process |
| `is_memfd` | bool | `true` / `false` | True for memfd-backed execution |

Network tool execution:

```yaml
rule_sets:
  - ruleset_id: acme/process
    rules:
      - rule_id: network_tool_exec
        event_type: process_exec
        condition: |
          process.exec_path.endsWith("/curl") ||
          process.exec_path.endsWith("/wget") ||
          process.exec_path.endsWith("/nc")
        action: collect
```

Shell started as a descendant of an installer or package manager:

```yaml
rule_sets:
  - ruleset_id: acme/process
    rules:
      - rule_id: shell_from_package_manager
        event_type: process_exec
        condition: |
          (
            process.exec_path.endsWith("/sh") ||
            process.exec_path.endsWith("/bash")
          ) &&
          process.ancestors.exists(parent,
            parent.exec_path.endsWith("/npm") ||
            parent.exec_path.endsWith("/pip") ||
            parent.exec_path.endsWith("/bundle")
          )
        action: detect
```

memfd-backed execution:

```yaml
condition: is_memfd
```

Example event value:

```json
{
  "event_type": "process_exec",
  "process": {
    "exec_path": "/usr/bin/curl",
    "argv": ["curl", "-fsSL", "https://example.com/install.sh"],
    "ancestors": [
      {"exec_path": "/bin/bash", "argv": ["bash", "-c", "curl -fsSL https://example.com/install.sh"]}
    ]
  },
  "payload": {
    "is_memfd": false
  }
}
```

## `network_connect`

Evaluates outbound network connections.

| field | Type | Example value | Meaning |
| --- | --- | --- | --- |
| `remote_ip` | string | `203.0.113.10`, `2001:db8::1` | Destination IP address |
| `remote_port` | int | `443`, `53` | Destination port |
| `protocol` | string | `tcp`, `udp` | Protocol |
| `family` | string | `ipv4`, `ipv6` | Destination address family |
| `process` | object | `process.exec_path == "/usr/bin/curl"` | Process that created the connection |

Outbound TCP connection from curl / wget:

```yaml
rule_sets:
  - ruleset_id: acme/network
    rules:
      - rule_id: network_tool_outbound
        event_type: network_connect
        condition: |
          protocol == "tcp" &&
          remote_port == 443 &&
          (
            process.exec_path.endsWith("/curl") ||
            process.exec_path.endsWith("/wget")
          )
        action: collect
```

Connection to private networks:

```yaml
condition: |
  family == "ipv4" &&
  (
    inIpRange(remote_ip, "10.0.0.0/8") ||
    inIpRange(remote_ip, "172.16.0.0/12") ||
    inIpRange(remote_ip, "192.168.0.0/16")
  )
```

Example event value:

```json
{
  "event_type": "network_connect",
  "process": {
    "exec_path": "/usr/bin/curl",
    "argv": ["curl", "https://registry.npmjs.org/"]
  },
  "payload": {
    "remote_ip": "104.16.24.34",
    "remote_port": 443,
    "protocol": "tcp",
    "family": "ipv4"
  }
}
```

## `unix_socket_connect`

Evaluates Unix domain socket connections.

| field | Type | Example value | Meaning |
| --- | --- | --- | --- |
| `path` | string | `/run/docker.sock`, `@dbus-7` | Socket path. Abstract namespace sockets are represented as `@...`. |
| `socket_type` | string | `stream`, `dgram`, `seqpacket`, `unknown` | Socket type |
| `is_abstract` | bool | `true` / `false` | True for abstract namespace sockets |
| `process` | object | `process.exec_path == "/usr/bin/docker"` | Process that connected to the socket |

Docker socket access:

```yaml
rule_sets:
  - ruleset_id: acme/socket
    rules:
      - rule_id: docker_socket_access
        event_type: unix_socket_connect
        condition: |
          socket_type == "stream" &&
          !is_abstract &&
          (
            path == "/var/run/docker.sock" ||
            path == "/run/docker.sock"
          )
        action: detect
```

Example event value:

```json
{
  "event_type": "unix_socket_connect",
  "process": {
    "exec_path": "/usr/bin/docker",
    "argv": ["docker", "ps"]
  },
  "payload": {
    "path": "/run/docker.sock",
    "socket_type": "stream",
    "is_abstract": false
  }
}
```

## `file_open`

Evaluates file open events.

| field | Type | Example value | Meaning |
| --- | --- | --- | --- |
| `path` | string | `/home/runner/.npmrc`, `/workspace/.env` | Opened file path |
| `is_read` | bool | `true` / `false` | True when read access is included |
| `is_write` | bool | `true` / `false` | True when write access is included |
| `flags` | int | `0`, `66` | Open flags |
| `process` | object | `process.exec_path == "/bin/cat"` | Process that opened the file |

Credential file read:

```yaml
rule_sets:
  - ruleset_id: acme/file
    rules:
      - rule_id: package_credential_read
        event_type: file_open
        condition: |
          is_read &&
          (
            path.endsWith("/.npmrc") ||
            path.endsWith("/.pypirc") ||
            path.endsWith("/.docker/config.json")
          )
        action: collect
```

Credential file read by a descendant of a shell:

```yaml
condition: |
  is_read &&
  path.endsWith("/.npmrc") &&
  process.ancestors.exists(parent,
    parent.exec_path.endsWith("/sh") ||
    parent.exec_path.endsWith("/bash")
  )
```

Example event value:

```json
{
  "event_type": "file_open",
  "process": {
    "exec_path": "/bin/cat",
    "argv": ["cat", "/home/runner/.npmrc"]
  },
  "payload": {
    "path": "/home/runner/.npmrc",
    "is_read": true,
    "is_write": false,
    "flags": 0
  }
}
```

## `file_remove`

Evaluates file or directory removal.

| field | Type | Example value | Meaning |
| --- | --- | --- | --- |
| `path` | string | `/workspace/.env`, `/var/log/journal` | Removed path |
| `is_folder` | bool | `true` / `false` | True for directory removal |
| `process` | object | `process.exec_path == "/bin/rm"` | Process that removed the path |

Secret file removal:

```yaml
condition: |
  !is_folder &&
  (
    path.endsWith("/.npmrc") ||
    path.endsWith("/.pypirc")
  )
```

Use `!is_folder` when you want to exclude directory removals and match only file unlink events.

Example event value:

```json
{
  "event_type": "file_remove",
  "process": {
    "exec_path": "/bin/rm",
    "argv": ["rm", "/workspace/.env"]
  },
  "payload": {
    "path": "/workspace/.env",
    "is_folder": false
  }
}
```

## `file_move`

Evaluates rename / move events.

| field | Type | Example value | Meaning |
| --- | --- | --- | --- |
| `from_path` | string | `/tmp/payload.bin` | Original path |
| `to_path` | string | `/usr/local/bin/curl` | New path |
| `process` | object | `process.exec_path == "/bin/mv"` | Process that renamed / moved the path |

Move from a temporary path to an executable path:

```yaml
condition: |
  from_path.startsWith("/tmp/") &&
  (
    to_path.startsWith("/usr/local/bin/") ||
    to_path.startsWith("/usr/bin/")
  )
```

Example event value:

```json
{
  "event_type": "file_move",
  "process": {
    "exec_path": "/bin/mv",
    "argv": ["mv", "/tmp/payload.bin", "/usr/local/bin/curl"]
  },
  "payload": {
    "from_path": "/tmp/payload.bin",
    "to_path": "/usr/local/bin/curl"
  }
}
```

## `file_link`

Evaluates hardlink / symlink creation.

| field | Type | Example value | Meaning |
| --- | --- | --- | --- |
| `created_path` | string | `/tmp/copy`, `/usr/local/bin/curl` | Newly created link / symlink path |
| `existing_path` | string | `/etc/shadow`, `/tmp/wrapper` | Existing target path |
| `is_hardlink` | bool | `true` / `false` | True for hardlinks |
| `is_symlink` | bool | `true` / `false` | True for symlinks |
| `process` | object | `process.exec_path == "/bin/ln"` | Process that created the link |

Hardlink to `/etc/shadow`:

```yaml
condition: is_hardlink && existing_path == "/etc/shadow"
```

Symlink from a temporary path to an executable path:

```yaml
condition: |
  is_symlink &&
  created_path.startsWith("/usr/local/bin/") &&
  existing_path.startsWith("/tmp/")
```

Example event value:

```json
{
  "event_type": "file_link",
  "process": {
    "exec_path": "/bin/ln",
    "argv": ["ln", "-s", "/tmp/wrapper", "/usr/local/bin/curl"]
  },
  "payload": {
    "created_path": "/usr/local/bin/curl",
    "existing_path": "/tmp/wrapper",
    "is_hardlink": false,
    "is_symlink": true
  }
}
```

## `domain`

Evaluates domain access.

| field | Type | Example value | Meaning |
| --- | --- | --- | --- |
| `domain` | string | `registry.npmjs.org`, `example.com` | Query domain. Lowercase, with trailing dot removed. |
| `source` | string | `dns` | Observation source. Currently mainly `dns`. |
| `process` | object | `process.exec_path == "/usr/bin/npm"` | Process that caused the domain access |

Access outside known internal domains:

```yaml
condition: |
  source == "dns" &&
  !domain.endsWith(".corp.example.com")
```

Suspicious domain access from a package-manager descendant:

```yaml
condition: |
  source == "dns" &&
  process.ancestors.exists(parent,
    parent.exec_path.endsWith("/npm") ||
    parent.exec_path.endsWith("/pip")
  )
```

Example event value:

```json
{
  "event_type": "domain",
  "process": {
    "exec_path": "/usr/bin/npm",
    "argv": ["npm", "install"]
  },
  "payload": {
    "domain": "registry.npmjs.org",
    "source": "dns"
  }
}
```
