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
import re
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
# Inherited propagation settings would change what the extractor does: with "baggage" left out
# (the workaround older images set), extraction returns nothing and a vulnerable ddtrace passes.
_PROPAGATION_ENV = re.compile(r"^(DD|OTEL)_.*PROPAGAT")


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        cwd=REPO_ROOT,
        env={**{k: v for k, v in os.environ.items() if not _PROPAGATION_ENV.match(k)}, **DD_ENV},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,  # the callers assert on returncode and show stderr
    )


def test_monitoring_setup_runs_without_ddtrace_warnings():
    """The ddtrace code the PDP runs works on the installed ddtrace:

    - OPAL's: opal_common.logger imports opal_common.monitoring.apm in every process (``patch``,
      ``tracer``, ``TraceFilter``), configure_logs calls ``fix_ddtrace_logging``, and the topic
      publisher wraps each publish in ``tracer.trace``. opal-client never calls ``configure_apm``
      (only opal-server does), so OPAL_ENABLE_DATADOG_APM does nothing in the PDP.
    - horizon's ``_configure_monitoring`` (``patch(fastapi=True)`` and ``config.fastapi``), run
      when monitoring is on. A FastAPI app built after it must be patched and serve a request.

    A removal is announced as a deprecation one major ahead, so any DDTraceDeprecationWarning fails
    too. Filtered by category: ddtrace warns with a stacklevel, so the filename is the caller's."""
    result = _run(
        """
        import warnings
        warnings.simplefilter("always")
        from ddtrace import DDTraceDeprecationWarning
        with warnings.catch_warnings(record=True) as caught:
            from opal_common.logger import configure_logs
            configure_logs()
            from ddtrace import tracer
            with tracer.trace("topic_publisher.publish", resource="['policy_data']"):
                pass
            from horizon.pdp import PermitPDP
            PermitPDP._configure_monitoring(object())  # self is unused
            import fastapi
            from fastapi.testclient import TestClient
            app = fastapi.FastAPI()
            app.get("/probe")(lambda: {"ok": True})
            assert TestClient(app).get("/probe").json() == {"ok": True}
        assert getattr(fastapi, "_datadog_patch", False), "patch(fastapi=True) did not patch FastAPI"
        ours = [str(w.message) for w in caught if issubclass(w.category, DDTraceDeprecationWarning)]
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
    # 0 would mean extraction is off, not that it is bounded: that passes on a vulnerable ddtrace.
    assert 0 < int(result.stdout.strip().splitlines()[-1]) <= 64
