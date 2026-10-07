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
TEMPLATE = ["template", "pdp", str(CHART), "--namespace", "pdp"]
EXISTING_SECRET = {"existingApiKeySecret": {"name": "pdp-api-key", "key": "api-key"}}
USER_PROVIDED_SECRET = {
    "userProvidedSecret": True,
    "pdpEnvs": [{"name": "PDP_API_KEY", "value": "vault:secret/data/pdp#api-key"}],
}
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
    result = _helm_run(tmp_path, TEMPLATE, values)
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def _of_kind(docs: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [doc for doc in docs if doc["kind"] == kind]


def _pod_spec(docs: list[dict[str, Any]]) -> dict[str, Any]:
    [deployment] = _of_kind(docs, "Deployment")
    return deployment["spec"]["template"]["spec"]


def _pdp_env(docs: list[dict[str, Any]], *names: str) -> list[dict[str, Any]]:
    """The PDP container's env entries with the given names, in render order."""
    [container] = [c for c in _pod_spec(docs)["containers"] if c["name"] == "permitio-pdp"]
    return [entry for entry in container.get("env") or [] if entry["name"] in names]


@pytest.mark.parametrize(
    "values",
    [
        pytest.param(None, id="defaults"),
        pytest.param({"pdp": SCHEDULING}, id="scheduling"),
        pytest.param({"pdp": EXISTING_SECRET}, id="existing-secret"),
        pytest.param({"pdp": USER_PROVIDED_SECRET}, id="user-provided-secret"),
        pytest.param({"pdp": {"userProvidedSecret": True}}, id="user-provided-secret-without-envs"),
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


@pytest.mark.parametrize(
    "values",
    [
        pytest.param(None, id="defaults"),
        pytest.param({"pdp": {"userProvidedSecret": False}}, id="user-provided-secret-off"),
        # A null in a values file removes the key, which must read as false.
        pytest.param({"pdp": {"userProvidedSecret": None}}, id="user-provided-secret-null"),
    ],
)
def test_api_key_comes_from_the_chart_secret_by_default(tmp_path, values):
    docs = _render(tmp_path, values)
    [secret] = _of_kind(docs, "Secret")
    assert secret["metadata"]["name"] == "permitio-pdp-secret"
    assert set(secret["data"]) == {"ApiKey"}
    assert _pdp_env(docs, "PDP_API_KEY") == [
        {"name": "PDP_API_KEY", "valueFrom": {"secretKeyRef": {"name": "permitio-pdp-secret", "key": "ApiKey"}}}
    ]


def test_existing_secret_replaces_the_chart_secret(tmp_path):
    docs = _render(tmp_path, {"pdp": EXISTING_SECRET})
    assert not _of_kind(docs, "Secret")
    assert _pdp_env(docs, "PDP_API_KEY") == [
        {"name": "PDP_API_KEY", "valueFrom": {"secretKeyRef": {"name": "pdp-api-key", "key": "api-key"}}}
    ]


def test_user_provided_secret_leaves_the_api_key_to_pdp_envs(tmp_path):
    docs = _render(tmp_path, {"pdp": USER_PROVIDED_SECRET})
    assert not _of_kind(docs, "Secret")
    assert _pdp_env(docs, "PDP_API_KEY") == [{"name": "PDP_API_KEY", "value": "vault:secret/data/pdp#api-key"}]


def test_user_provided_secret_without_pdp_envs_sets_no_api_key(tmp_path):
    docs = _render(tmp_path, {"pdp": {"userProvidedSecret": True}})
    assert not _of_kind(docs, "Secret")
    assert not _pdp_env(docs, "PDP_API_KEY")


def test_user_provided_secret_and_existing_secret_together_fail_to_render(tmp_path):
    result = _helm_run(tmp_path, TEMPLATE, {"pdp": {**EXISTING_SECRET, **USER_PROVIDED_SECRET}})
    assert result.returncode != 0
    assert "pdp.userProvidedSecret and pdp.existingApiKeySecret cannot both be set" in result.stderr


@pytest.mark.parametrize("value", ["false", "true"])
def test_user_provided_secret_given_as_a_string_fails_to_render(tmp_path, value):
    # A quoted "false" is truthy in a template, so without this check it would drop PDP_API_KEY.
    result = _helm_run(tmp_path, TEMPLATE, {"pdp": {"userProvidedSecret": value}})
    assert result.returncode != 0
    assert f'pdp.userProvidedSecret must be true or false, got the string "{value}"' in result.stderr
