"""OPAL's log scrubbing stays installed under the PDP (PER-16197).

From OPAL 0.10 (0.9.8 on the 0.9 line), opal_common.logger.configure_logs installs a loguru
patcher that scrubs credentials embedded in URLs. loguru keeps one patcher, and
`logger.configure(patcher=...)` replaces it, so a patcher the PDP installed the same way would
silently switch OPAL's off. The PDP installs none; it calls `logger.configure(extra=...)`, which
leaves the patcher alone. This checks both, in a child interpreter because configure_logs
reconfigures loguru process-wide.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_opal_patcher_survives_the_pdp_logger_setup():
    code = textwrap.dedent(
        """
        import io
        from loguru import logger
        from opal_common.logger import configure_logs
        configure_logs()
        out = io.StringIO()
        logger.add(out, format="{message}")
        logger.configure(extra={"pdp_instance_id": "x"})  # what horizon/pdp.py does after OPAL's setup
        logger.info("fetch failed for https://user:not-a-real-secret@example.com/data")
        print(out.getvalue())
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,  # asserted below, with stderr
    )
    assert result.returncode == 0, result.stderr
    # The whole line, not a substring check: the host survives, the credentials do not.
    assert result.stdout.splitlines()[0] == "fetch failed for https://***@example.com/data", result.stdout
    assert "not-a-real-secret" not in result.stdout


def test_horizon_installs_no_loguru_patcher_of_its_own():
    """A horizon patcher would replace OPAL's (see the module docstring). If one is ever needed,
    it must call OPAL's scrubber too; update this test when that is done deliberately."""
    offenders = [
        f"{path.relative_to(REPO_ROOT)}"
        for path in (REPO_ROOT / "horizon").rglob("*.py")
        if "tests" not in path.parts and "patcher=" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
