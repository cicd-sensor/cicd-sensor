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
Each ancestor exposes `exec_path`, `argv`, and `descendants`.
`descendants` contains only the processes forked below that ancestor on the path to the current process.
It is ordered from that ancestor toward the current process: parent -> child.
It does not include the current process itself.

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

## `mount`

Evaluates mount attempts that may expose or relocate a mount tree through
another path. The event records classic bind and move requests and new-API
`move_mount` requests from tracked jobs. It does not represent every
filesystem mount, and the recorded attempt is not guaranteed to have
succeeded.

| field | Type | Example value | Meaning |
| --- | --- | --- | --- |
| `source_path` | string | `/tmp/source` | Mount source. For classic `mount(2)`, this is the raw source string |
| `target_path` | string | `/mnt/target` | Mount target path |
| `process` | object | `process.exec_path == "/bin/mount"` | Process that attempted the mount |

Because a classic `source_path` may be relative, symlinked, or otherwise
non-canonical, source matching is a best-effort signal rather than a strict
security boundary.

Protected path exposed through another location:

```yaml
condition: source_path.startsWith("/protected/") && !target_path.startsWith("/protected/")
```

Example event value:

```json
{
  "event_type": "mount",
  "process": {
    "exec_path": "/bin/mount",
    "argv": ["mount", "--bind", "/tmp/source", "/mnt/target"]
  },
  "payload": {
    "source_path": "/tmp/source",
    "target_path": "/mnt/target"
  }
}
```

The paths describe the mount operation, not a canonical identity for later file
writes. The classic mount source is the raw source string supplied to the mount
operation. Target paths and new-API move paths use a filesystem-rooted dentry
walk and can expose node-side backing paths for Kubernetes volumes. A
`move_mount` event can represent a detached mount attachment, a mount tree
relocation, or another operation routed through the same kernel hook; rules
should rely on path and process context rather than infer that distinction.

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

## `http_request`

Evaluates the request line of an outgoing HTTP request: method, path, and host together.
Only the request line and the `Host` header are captured. Other headers and the body are not captured.

HTTP uprobe sources (`openssl`, `nghttp2`, and `go_net_http`) are currently
disabled by default. Enable them with `--enable-uprobes=true`. Plain HTTP
capture remains available as `cleartext_http`.

| field | Type | Example value | Meaning |
| --- | --- | --- | --- |
| `method` | string | `get`, `post` | Request method |
| `path` | string | `/repos/cli/cli/releases` | Request path with the query string removed |
| `host` | string | `api.github.com`, `example.com:8080` | Request host; may include a port |
| `source` | string | `cleartext_http`, `openssl`, `nghttp2`, `go_net_http` | Capture source |
| `process` | object | `process.exec_path == "/usr/bin/curl"` | Process that sent the request |

`source` reports where the request line was read:

- `cleartext_http`: plain HTTP traffic
- `openssl`: HTTPS over HTTP/1.x through a supported OpenSSL client
- `nghttp2`: HTTP/2 through a supported nghttp2 client
- `go_net_http`: HTTP requests from a supported Go `net/http` client

`http_request` does not cover every HTTP client or protocol. The absence of this
event does not prove that no outbound communication occurred. Use
`network_connect` rules for general egress coverage, and combine them with
`domain` rules when DNS observations are available.

Event string values and rule string literals are normalized to lowercase.
String comparisons are therefore case-insensitive. For example,
`method == "POST"` and `method == "post"` are equivalent.

Unexpected POST to the GitHub API:

```yaml
condition: |
  method == "POST" &&
  host == "api.github.com" &&
  !process.exec_path.endsWith("/git")
```

Cloud metadata service access:

```yaml
condition: |
  host == "169.254.169.254"
```

Example event value:

```json
{
  "event_type": "http_request",
  "process": {
    "exec_path": "/usr/bin/curl",
    "argv": ["curl", "http://api.example.com/upload"]
  },
  "payload": {
    "method": "post",
    "path": "/upload",
    "host": "api.example.com",
    "source": "cleartext_http"
  }
}
```
