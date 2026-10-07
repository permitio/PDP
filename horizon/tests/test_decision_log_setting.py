"""Which PDP_OPA_DECISION_LOG_ENABLED a PDP ends up with, its own or the control plane's.

The control plane sends OPA_DECISION_LOG_ENABLED to every PDP with its config overrides. A boolean
set in the PDP's environment is kept; without one, or with an empty or non-boolean value, the
control plane's value is used.

Each case runs in a new interpreter, because horizon.config reads the environment once, at import.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_NAME = "PDP_OPA_DECISION_LOG_ENABLED"
ROUTE = "/v1/decision_logs/custom-ingress"


def _apply_overrides(env_value: str | None, overrides: dict) -> tuple[dict, str]:
    """Start with ENV_NAME set to env_value (unset for None), apply the overrides as the PDP does.

    Returns the resulting decision log settings and everything the interpreter logged.
    """
    env = {name: value for name, value in os.environ.items() if name != ENV_NAME}
    if env_value is not None:
        env[ENV_NAME] = env_value
    code = (
        "import json, sys\n"
        "from horizon.config import sidecar_config\n"
        "from horizon.pdp import apply_pdp_overrides\n"
        "apply_pdp_overrides(json.loads(sys.argv[1]))\n"
        "print(json.dumps({'enabled': sidecar_config.OPA_DECISION_LOG_ENABLED,"
        " 'route': sidecar_config.OPA_DECISION_LOG_INGRESS_ROUTE}))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, json.dumps(overrides)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.splitlines()[-1]), result.stderr


def test_false_set_for_the_pdp_is_kept_over_the_control_plane_true():
    settings, logged = _apply_overrides(
        "false", {"OPA_DECISION_LOG_ENABLED": True, "OPA_DECISION_LOG_INGRESS_ROUTE": ROUTE}
    )

    assert settings == {"enabled": False, "route": ROUTE}
    assert f"{ENV_NAME} is set for this PDP (False); using it instead of the control plane's value (True)." in logged


def test_true_set_for_the_pdp_is_kept_over_the_control_plane_false():
    settings, logged = _apply_overrides(
        "true", {"OPA_DECISION_LOG_ENABLED": False, "OPA_DECISION_LOG_INGRESS_ROUTE": ROUTE}
    )

    assert settings == {"enabled": True, "route": ROUTE}
    assert f"{ENV_NAME} is set for this PDP (True); using it instead of the control plane's value (False)." in logged


def test_without_a_value_set_for_the_pdp_the_control_plane_value_is_used():
    settings, logged = _apply_overrides(
        None, {"OPA_DECISION_LOG_ENABLED": False, "OPA_DECISION_LOG_INGRESS_ROUTE": ROUTE}
    )

    assert settings == {"enabled": False, "route": ROUTE}
    assert f"{ENV_NAME} is not set for this PDP; using the control plane's value (False)." in logged


@pytest.mark.parametrize("env_value", ["", "maybe"], ids=["empty", "not-a-boolean"])
def test_a_pdp_value_that_is_not_a_boolean_is_ignored_with_a_warning(env_value: str):
    settings, logged = _apply_overrides(
        env_value, {"OPA_DECISION_LOG_ENABLED": False, "OPA_DECISION_LOG_INGRESS_ROUTE": ROUTE}
    )

    assert settings == {"enabled": False, "route": ROUTE}
    message = (
        f"{ENV_NAME} is set to {env_value!r}, which is not true, false, 1 or 0; "
        "using the control plane's value (False)."
    )
    assert [line for line in logged.splitlines() if message in line and "WARNING" in line]


def test_a_control_plane_that_sends_no_value_leaves_the_pdp_value_alone():
    settings, logged = _apply_overrides("false", {"OPA_DECISION_LOG_INGRESS_ROUTE": ROUTE})

    assert settings == {"enabled": False, "route": ROUTE}
    assert ENV_NAME not in logged
