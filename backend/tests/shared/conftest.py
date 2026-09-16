"""Shared-engine tests import ``shared`` from the repository root.

Both real callers bootstrap that path themselves - the platform through
``app.services.sensitive_engine`` and the probe through its own ``sys.path``
insertion - so the tests mirror the same import path instead of installing the
package.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
