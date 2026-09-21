#!/bin/bash
# Only used inside a disposable, network-disabled Ubuntu container.
set -euo pipefail
! command -v python3
! command -v pip
! command -v dumpcap
! command -v tcpdump
mkdir -p /tmp/package /opt/data-security-toolbox/venv/bin /etc/data-security-toolbox
tar -xzf /package/probe-3.7.0-*.tar.gz -C /tmp/package
printf '#!/bin/sh\nexit 97\n' > /opt/data-security-toolbox/venv/bin/python
chmod +x /opt/data-security-toolbox/venv/bin/python
printf 'existing-identity' > /etc/data-security-toolbox/probe.token
# Service management is recorded; actual runtime/capture execute below without systemd.
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> /tmp/systemctl.calls\n' > /usr/bin/systemctl
chmod +x /usr/bin/systemctl
bash /tmp/package/install.sh --install-only
grep -q 'ExecStart=/opt/data-security-toolbox/run-probe.sh' /etc/systemd/system/data-security-toolbox-probe.service
test "$(cat /etc/data-security-toolbox/probe.token)" = existing-identity
/opt/data-security-toolbox/run-probe.sh --help
grep -q 'Environment=PYTHONUTF8=1' /etc/systemd/system/data-security-toolbox-probe.service
grep -q 'runtime/bin/python' /opt/data-security-toolbox/run-probe.sh
grep -q -- '-X utf8' /opt/data-security-toolbox/run-probe.sh
# The launcher must work with an empty environment and a C locale: it sets PATH
# itself (systemd may start the service with almost nothing) and pins UTF-8, so
# non-ASCII log lines survive on a host without a UTF-8 locale.
env -i /bin/bash -c 'cd / && LC_ALL=C LANG=C /opt/data-security-toolbox/run-probe.sh --help' >/tmp/help.txt
grep -q 'usage:' /tmp/help.txt
cat > /tmp/unicode_check.py <<'PY'
open('/tmp/unicode.txt', 'w', encoding='utf-8').write('中文目录 /var/lib/dst/报告')
PY
env -i /bin/sh -c 'PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C /opt/data-security-toolbox/runtime/bin/python -X utf8 /tmp/unicode_check.py'
grep -q '报告' /tmp/unicode.txt
set +e
env -i /bin/bash -c 'LC_ALL=C LANG=C /opt/data-security-toolbox/run-probe.sh --config /tmp/absent.toml' >/tmp/absent.log 2>&1
set -e
test -s /tmp/absent.log
! grep -q 'UnicodeEncodeError\|UnicodeDecodeError' /tmp/absent.log
setpriv --reuid dstprobe --regid dstprobe --init-groups \
  --inh-caps +net_raw,+net_admin --ambient-caps +net_raw,+net_admin \
  /opt/data-security-toolbox/runtime/bin/python -s /checks/smoke.py
# Reinstall must also ignore the old venv and retain identity and spool state.
touch /var/lib/data-security-toolbox/spool/keep
bash /tmp/package/install.sh --install-only
test "$(cat /etc/data-security-toolbox/probe.token)" = existing-identity
test -f /var/lib/data-security-toolbox/spool/keep
bash /opt/data-security-toolbox/uninstall.sh --keep-data --keep-user
test ! -e /opt/data-security-toolbox
test -f /var/lib/data-security-toolbox/spool/keep
echo 'PASS: offline install, old-venv isolation, reinstall, identity/data preservation, uninstall'
