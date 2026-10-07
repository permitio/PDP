"""Render tests for the Helm chart in charts/pdp.

They live here because the required `pytests` job runs exactly
`pytest -s --cache-clear horizon/tests/`, and that job installs Helm for them. Without Helm on
PATH they skip locally and fail in CI, so a runner that lost Helm cannot pass them silently.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

CHART = Path(__file__).resolve().parents[2] / "charts" / "pdp"
SCHEDULING_KEYS = {"nodeSelector", "tolerations", "affinity"}
SCHEDULING = {
    "nodeSelector": {"pool": "pdp"},
    "tolerations": [{"key": "dedicated", "operator": "Equal", "value": "pdp", "effect": "NoSchedule"}],
    "affinity": {
        "nodeAffinity": {
            "requiredDuringSchedulingIgnoredDuringExecution": {
                "nodeSelectorTerms": [{"matchExpressions": [{"key": "pool", "operator": "In", "values": ["pdp"]}]}]
            }
        }
    },
}


def _helm() -> str:
    helm = shutil.which("helm")
    if helm is None:
        message = "helm is not on PATH: install Helm to run the chart tests"
        if os.environ.get("CI"):
            pytest.fail(message)
        pytest.skip(message)
    return helm


def _helm_run(tmp_path: Path, command: list[str], values: dict[str, Any] | None) -> subprocess.CompletedProcess[str]:
    args = [_helm(), *command]
    if values is not None:
        values_file = tmp_path / "values.yaml"
        values_file.write_text(yaml.safe_dump(values), encoding="utf-8")
        args += ["--values", str(values_file)]
    return subprocess.run(args, capture_output=True, text=True, check=False)


def _render(tmp_path: Path, values: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    result = _helm_run(tmp_path, ["template", "pdp", str(CHART), "--namespace", "pdp"], values)
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def _pod_spec(docs: list[dict[str, Any]]) -> dict[str, Any]:
    [deployment] = [doc for doc in docs if doc["kind"] == "Deployment"]
    return deployment["spec"]["template"]["spec"]


@pytest.mark.parametrize(
    "values",
    [
        pytest.param(None, id="defaults"),
        pytest.param({"pdp": SCHEDULING}, id="scheduling"),
    ],
)
def test_chart_lints_clean(tmp_path, values):
    result = _helm_run(tmp_path, ["lint", "--strict", str(CHART)], values)
    assert result.returncode == 0, result.stdout + result.stderr


def test_default_render_sets_no_scheduling_constraints(tmp_path):
    assert not SCHEDULING_KEYS & _pod_spec(_render(tmp_path)).keys()


def test_scheduling_values_reach_the_pod_spec(tmp_path):
    pod = _pod_spec(_render(tmp_path, {"pdp": SCHEDULING}))
    assert {key: pod[key] for key in SCHEDULING_KEYS} == SCHEDULING


@pytest.mark.parametrize("key", sorted(SCHEDULING_KEYS))
def test_each_scheduling_value_renders_on_its_own(tmp_path, key):
    pod = _pod_spec(_render(tmp_path, {"pdp": {key: SCHEDULING[key]}}))
    assert pod[key] == SCHEDULING[key]
    assert not (SCHEDULING_KEYS - {key}) & pod.keys()


@pytest.mark.parametrize(
    ("values", "volumes"),
    [
        pytest.param(
            {"pdp": {"logs_forwarder": {"enabled": True}}}, ["fluent-bit-config", "logs"], id="logs-forwarder"
        ),
        pytest.param({"openshift": {"enabled": True}}, ["tmp-volume", "opa-volume"], id="openshift"),
    ],
)
def test_scheduling_values_sit_beside_the_optional_volumes(tmp_path, values, volumes):
    pod = _pod_spec(_render(tmp_path, {**values, "pdp": {**values.get("pdp", {}), **SCHEDULING}}))
    assert {key: pod[key] for key in SCHEDULING_KEYS} == SCHEDULING
    assert [volume["name"] for volume in pod["volumes"]] == volumes
