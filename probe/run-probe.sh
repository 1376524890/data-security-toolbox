#!/bin/sh
# Launcher for the self-contained probe runtime.
#
# Only shell builtins are used to locate the application directory, so the
# service does not depend on the target's PATH being set (systemd may start it
# with a minimal environment, and `dirname` would not be found there).
#
# The locale is pinned to UTF-8 on purpose: under a C/POSIX locale the bundled
# interpreter would use ASCII for stdio, so any non-ASCII log line (Chinese
# file names, rule-pack messages) would be escaped or raise UnicodeEncodeError.
set -eu
case "$0" in
  */*) APP_DIR="${0%/*}" ;;
  *) APP_DIR="." ;;
esac
APP_DIR="$(cd "${APP_DIR}" && pwd -P)"
PATH="/usr/sbin:/usr/bin:/sbin:/bin"
PYTHONUTF8=1
PYTHONIOENCODING=utf-8
export PATH PYTHONUTF8 PYTHONIOENCODING
exec "${APP_DIR}/runtime/bin/python" -X utf8 -s "${APP_DIR}/probe/probe.py" "$@"
