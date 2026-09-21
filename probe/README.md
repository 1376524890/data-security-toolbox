# Probe Agent

The probe is a long-running daemon responsible for capture, local spooling,
authenticated upload, heartbeat, and lightweight local inventory. Detection,
risk, and alerting run in the backend analysis worker.

Every package ships a **self-contained runtime** (`runtime.tar.gz`): a private
CPython 3.11, the Python dependencies (`requests`, `psutil`, `regex`,
`openpyxl`), `dumpcap` and `tcpdump`, their ELF library closure, a private
dynamic loader and a CA bundle. The target host needs no Python, pip, apt,
wheel directory or capture tool, and nothing is written to `/usr/local/bin`.

The only host prerequisites are systemd and a basic coreutils/shadow tool set
(`tar`, `systemctl`, `useradd`, `id`, `chown`, `find`, `mktemp`). `install.sh`
checks for all of them up front and aborts with the complete missing list
before it touches the running installation.

`ExecStart` is the fixed launcher `/opt/data-security-toolbox/run-probe.sh`. It
locates its own directory with shell builtins only (no `dirname`), sets
`PATH=/usr/sbin:/usr/bin:/sbin:/bin` itself, and pins `PYTHONUTF8=1` /
`PYTHONIOENCODING=utf-8` before exec'ing `runtime/bin/python -X utf8 -s`. Both
matter on a minimal host: systemd starts the unit with an almost empty
environment, and with `LANG` unset the bundled interpreter would fall back to
a C/POSIX locale and use ASCII for stdio, so non-ASCII log lines (Chinese file
names, rule-pack messages) would be escaped or fail outright.

## Install

```bash
sudo ./install.sh [--config /path/to/probe.toml] [--ca /path/to/ca.pem]
```

`install.sh` runs the bundled interpreter against `runtime_check.py` before it
touches the running installation, then stops the service, atomically replaces
`/opt/data-security-toolbox/runtime`, and keeps the existing
`/etc/data-security-toolbox/probe.toml`, `probe.token` and everything under
`/var/lib/data-security-toolbox` (spool, rules, cache). `--skip-deps` is gone:
there is nothing to install from a package index.

Edit `/etc/data-security-toolbox/probe.toml`, set the bootstrap token, then restart:

```bash
sudo systemctl restart data-security-toolbox-probe
```

The service runs as `dstprobe` with `CAP_NET_RAW`, `CAP_NET_ADMIN` and
`CAP_DAC_READ_SEARCH`, uses `Restart=always` and `RestartSec=5`, and never runs
as root. A directory the probe cannot read is reported as a coverage gap rather
than retried with wider privileges. The runtime tree is owned by `root:root` and
is not writable by `dstprobe`.

## Upgrade and rollback

`install.sh` is idempotent, so an in-place upgrade is the same command from the
new package directory:

```bash
tar -xzf probe-<new>-amd64.tar.gz -C /tmp/probe-<new>
sudo bash /tmp/probe-<new>/install.sh
```

The probe identity (`probe.token`), configuration and pending spool survive the
upgrade; a failed install exits before the runtime is swapped. Keep the previous
package directory to roll back — reinstalling it is the rollback:

```bash
sudo bash /path/to/probe-<previous>/install.sh
```

## Manual run

```bash
/opt/data-security-toolbox/run-probe.sh --config /etc/data-security-toolbox/probe.toml
# equivalently
/opt/data-security-toolbox/runtime/bin/python -X utf8 -s /opt/data-security-toolbox/probe/probe.py --config /etc/data-security-toolbox/probe.toml
```

## Uninstall

```bash
sudo /opt/data-security-toolbox/uninstall.sh [--keep-data] [--keep-user] [--dry-run]
```

## Behavior

- The runtime wrappers unset `LD_PRELOAD`/`LD_AUDIT`/`LD_LIBRARY_PATH`/`PYTHON*`
  and invoke the bundled loader, so the host libc, OpenSSL or extension
  libraries cannot leak into the probe process.
- Capture uses `dumpcap` first and falls back to `tcpdump`.
- Segments are written to `spool/*.pcapng.partial`, fsynced, then atomically renamed.
- Uploads use `X-Probe-ID` and `X-Probe-Token`; retries use exponential backoff.
- Full spool stops capture and reports `capture_status=degraded` instead of deleting evidence.
- Local IP comes from the configured capture interface, never from an external resolver.
- Asset inventory checks only configured local ports and requires `connect_ex() == 0`.
- Asset inventory also grabs a short banner (`recv`) per open port to aid service fingerprinting.
- When `agent.file_interval_seconds > 0` and `agent.paths` are set, the probe uploads each target
  file's content to `/api/v1/files/upload` so the backend can run sensitive-data analysis on real
  bytes (PII/secret/YARA). Each record includes `sha256` and `md5`.
- Registration persists `probe_id + token` to `agent.identity_path` (0600) and never re-enrolls on
  restart. A platform deployment pushes a one-time enrollment token together with its
  `deployment_id`; while that token is present it outranks the stored identity, so deleting a probe
  and deploying again on the same host (or reinstalling on a host that once ran a probe) enrolls
  instead of reusing the retired `probe_id`. A rejected token falls back to the stored identity.
