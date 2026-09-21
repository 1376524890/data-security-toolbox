"""Guard the promise that the probe package runs on a bare target host.

The probe is delivered as a self-contained runtime, so no entry point may reach
for a host interpreter, a package index or the target's locale. These checks are
static on purpose: they fail in CI when a future edit reintroduces a host
dependency, long before a customer's server hits it.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PROBE = REPO / "probe"

#: Commands that would make the package depend on the target environment.
HOST_DEPENDENCIES = (
    r"\bpip3?\b",
    r"\bapt(-get)?\b",
    r"\bensurepip\b",
    r"/usr/bin/python",
    r"\bpython3\b",
)


def _statements(relative: str) -> str:
    """The file's commands, with comment-only lines removed.

    The installer documents *why* it never calls pip/apt/venv, and those words
    must not trip the scan.
    """
    text = (REPO / relative).read_text(encoding="utf-8")
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def test_launcher_uses_the_bundled_interpreter_and_pins_utf8():
    launcher = _statements("probe/run-probe.sh")
    assert "runtime/bin/python" in launcher
    assert "-X utf8" in launcher
    assert "PYTHONUTF8=1" in launcher
    assert "PYTHONIOENCODING=utf-8" in launcher
    # Shell builtins only: locating the app directory must not need PATH, because
    # systemd can start the unit with a minimal environment.
    assert "dirname" not in launcher
    lines = launcher.splitlines()
    assert lines.index('PATH="/usr/sbin:/usr/bin:/sbin:/bin"') < next(
        index for index, line in enumerate(lines) if line.startswith("exec ")
    )


def test_unit_files_pin_the_locale():
    for relative in ("probe/data-security-toolbox-probe.service", "probe/install.sh"):
        assert "Environment=PYTHONUTF8=1" in _statements(relative), relative


def test_installer_reports_missing_host_tools_and_installs_nothing():
    installer = _statements("probe/install.sh")
    assert "MISSING_TOOLS" in installer
    assert re.search(r"for tool in .*tar.*systemctl.*useradd", installer)
    for pattern in HOST_DEPENDENCIES:
        assert not re.search(pattern, installer), pattern
    # The runtime is validated with the bundled interpreter before anything is
    # replaced, and the bundled capture tools are never installed next to it.
    assert re.search(r"runtime/bin/python\" -X utf8 -s .*runtime_check\.py", installer)


def test_probe_sources_never_invoke_a_host_interpreter():
    sources = sorted(PROBE.glob("*.py")) + sorted((REPO / "shared").rglob("*.py"))
    assert len(sources) > 10
    for path in sources:
        text = path.read_text(encoding="utf-8")
        assert "ensurepip" not in text, path
        assert "/usr/bin/python" not in text, path
        assert not re.search(r"shutil\.which\(['\"]python", text), path


def test_runtime_self_check_covers_every_declared_dependency():
    requirements = [
        line.split("==")[0].strip().lower()
        for line in (PROBE / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert requirements == ["requests", "psutil", "regex", "openpyxl"]
    checker = (PROBE / "runtime_check.py").read_text(encoding="utf-8")
    for name in requirements:
        assert f"'{name}'" in checker, name
    # A host interpreter must be rejected, never silently used.
    assert "base_prefix" in checker
    assert "'python/bin/python3.11'" in checker
