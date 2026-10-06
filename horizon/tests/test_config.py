"""How horizon.config reads PDP_IGNORE_DEFAULT_DATA_UPDATE_CALLBACKS_URLS.

The PDP drops a default data-update callback whose URL is IN this setting. Read as a raw string, `in`
was a substring test, so a callback whose URL merely appears inside the JSON text was dropped too.
Plain text that worked as a raw string still works: an empty value, a bare URL, URLs separated by
commas or spaces.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from horizon.config import sidecar_config
from horizon.pdp import apply_config

REPO_ROOT = Path(__file__).resolve().parents[2]
SETTING = "IGNORE_DEFAULT_DATA_UPDATE_CALLBACKS_URLS"
CACHE_REBUILD = "http://localhost:8181/v1/data/permit/rebac/cache_rebuild"


def _shipped_value() -> str:
    """The value the Dockerfile sets, so a malformed default fails here and not at PDP startup."""
    match = re.search(rf"^ENV PDP_{SETTING}='(.*)'$", (REPO_ROOT / "Dockerfile").read_text(), re.MULTILINE)
    assert match is not None, f"Dockerfile no longer sets PDP_{SETTING} as ENV PDP_{SETTING}='...'"
    return match.group(1)


def _load_in_fresh_interpreter(env_value: str) -> subprocess.CompletedProcess[str]:
    """Import horizon.config with PDP_<SETTING> set and print the setting as JSON.

    A new interpreter, because the config singleton reads the environment once, at import.
    """
    code = f"import json; from horizon.config import sidecar_config; print(json.dumps(sidecar_config.{SETTING}))"
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        env={**os.environ, f"PDP_{SETTING}": env_value},
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_the_shipped_value_reads_as_a_list_of_urls():
    result = _load_in_fresh_interpreter(_shipped_value())

    assert result.returncode == 0, result.stderr
    urls = json.loads(result.stdout)
    assert urls == [CACHE_REBUILD]
    # The substring false positive the raw string allowed: a prefix of the ignored URL.
    assert "http://localhost:8181/v1/data/permit" not in urls


@pytest.mark.parametrize(
    ("env_value", "urls"),
    [
        # `docker run -e PDP_...=` or a Kubernetes `value: ""`: the way to clear the Dockerfile
        # default and keep the cache_rebuild callback.
        pytest.param("", [], id="empty"),
        pytest.param("   ", [], id="blank"),
        pytest.param(CACHE_REBUILD, [CACHE_REBUILD], id="bare-url"),
        pytest.param("http://a/cb, http://b/cb http://c/cb", ["http://a/cb", "http://b/cb", "http://c/cb"], id="list"),
    ],
)
def test_plain_text_reads_as_the_urls_it_holds(env_value: str, urls: list[str]):
    result = _load_in_fresh_interpreter(env_value)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == urls


@pytest.mark.parametrize("env_value", ['{"url": "http://a"}', "[1, [", '["http://a", ["nested"]]'])
def test_json_that_is_not_a_list_of_urls_stops_startup(env_value: str):
    result = _load_in_fresh_interpreter(env_value)

    assert result.returncode != 0
    assert f"PDP_{SETTING} must be a JSON list of URLs" in result.stderr


@pytest.mark.parametrize(
    ("override", "urls"),
    [
        pytest.param('["http://a/cb"]', ["http://a/cb"], id="json-text"),
        pytest.param(["http://a/cb"], ["http://a/cb"], id="json-list"),
        pytest.param("", [], id="empty"),
        pytest.param(None, [], id="null"),
    ],
)
def test_a_control_plane_override_replaces_the_shipped_urls(monkeypatch, override, urls):
    # Registered with monkeypatch first, so the override below is undone after the test.
    monkeypatch.setattr(sidecar_config, SETTING, [CACHE_REBUILD])

    apply_config({SETTING: override}, sidecar_config)

    assert getattr(sidecar_config, SETTING) == urls
