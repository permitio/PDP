"""The PDP's ddtrace paths against the installed ddtrace (PER-17853).

opal-common 0.9.6 caps ddtrace<4; the ``override-dependencies`` entry in pyproject.toml replaces
that cap so the image gets the CVE-2026-50271 fix (4.8.2). Nothing else exercises these paths:
monitoring is off by default (``PDP_ENABLE_MONITORING``), so a ddtrace major that broke them
would pass every other test.

Each check runs in a child interpreter. ``patch()`` instruments FastAPI process-wide, and importing
ddtrace has side effects of its own (see ``_configure_monitoring``), so neither may leak into the
rest of the suite.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
# No agent in tests: keep the tracer and its background services from reaching for one.
DD_ENV = {
    "DD_TRACE_ENABLED": "false",
    "DD_INSTRUMENTATION_TELEMETRY_ENABLED": "false",
    "DD_REMOTE_CONFIGURATION_ENABLED": "false",
}


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        cwd=REPO_ROOT,
        env={**os.environ, **DD_ENV},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,  # the callers assert on returncode and show stderr
    )


def test_monitoring_setup_runs_without_ddtrace_warnings():
    """horizon's ``_configure_monitoring`` and OPAL's ``configure_apm`` (what opal-client runs when
    ``OPAL_ENABLE_DATADOG_APM`` is on) both work on the installed ddtrace. A removal is announced as
    a deprecation one major ahead, so any ddtrace warning fails too."""
    result = _run(
        """
        import warnings
        warnings.simplefilter("always")
        with warnings.catch_warnings(record=True) as caught:
            from horizon.pdp import PermitPDP
            PermitPDP._configure_monitoring(object())  # self is unused
            from opal_common.monitoring.apm import configure_apm, fix_ddtrace_logging
            configure_apm(True, "opal-client")
            fix_ddtrace_logging()
        from ddtrace import config
        assert config.fastapi["service_name"] == "permit-pdp", config.fastapi["service_name"]
        ours = [str(w.message) for w in caught if "ddtrace" in (w.filename or "") or "ddtrace" in str(w.message)]
        assert not ours, ours
        """
    )
    assert result.returncode == 0, result.stderr


def test_baggage_extraction_is_bounded():
    """CVE-2026-50271 itself: ddtrace < 4.8.2 extracts every item of an inbound W3C ``baggage``
    header, ignoring DD_TRACE_BAGGAGE_MAX_ITEMS. 3.19.8 returns all 5000 items here; a fixed
    ddtrace returns at most the limit (default 64)."""
    result = _run(
        """
        from ddtrace.propagation.http import HTTPPropagator
        header = ",".join(f"k{i}=v{i}" for i in range(5000))
        context = HTTPPropagator.extract({
            "baggage": header,
            "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        })
        print(len(context.get_all_baggage_items()))
        """
    )
    assert result.returncode == 0, result.stderr
    assert int(result.stdout.strip().splitlines()[-1]) <= 64
