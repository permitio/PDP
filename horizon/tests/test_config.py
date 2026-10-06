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
from types import SimpleNamespace

import pytest
from loguru import logger
from opal_client.callbacks.register import CallbacksRegister

from horizon.config import SidecarConfig, sidecar_config
from horizon.pdp import PermitPDP, apply_config

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


@pytest.mark.parametrize(
    ("env_value", "urls"),
    [
        pytest.param('"http://a/cb"', ["http://a/cb"], id="double-quoted"),
        pytest.param("'http://a/cb', 'http://b/cb'", ["http://a/cb", "http://b/cb"], id="single-quoted"),
    ],
)
def test_quotes_around_plain_text_urls_are_dropped(env_value: str, urls: list[str]):
    assert SidecarConfig.parse_url_list(env_value) == urls


@pytest.mark.parametrize(
    ("env_value", "reason"),
    [
        pytest.param("['http://a/x']", "JSON needs double quotes around each URL", id="python-list"),
        pytest.param("[http://a/x, http://b/y]", "put each URL in double quotes", id="unquoted"),
        pytest.param('["http://a/x",]', "remove the trailing comma", id="trailing-comma"),
        pytest.param('{"url": "http://a/x"}', "it is a JSON object, not a list of URLs", id="object"),
        pytest.param("[1, 2]", "item 0 is 1, which is not a URL in double quotes", id="number"),
        pytest.param('["http://a/x", ["nested"]]', 'item 1 is ["nested"]', id="nested"),
    ],
)
def test_a_malformed_value_names_the_problem_and_the_accepted_forms(env_value: str, reason: str):
    with pytest.raises(ValueError, match="is invalid") as exc_info:
        SidecarConfig.parse_url_list(env_value)

    message = str(exc_info.value)
    assert message.startswith(f"PDP_{SETTING} is invalid: ")
    assert reason in message
    assert f"Got: {env_value}" in message
    assert '["http://localhost:8181/v1/data/permit/rebac/cache_rebuild"]' in message
    assert "separated by commas or spaces" in message
    assert "an empty value" in message
    assert "exactly" in message


def test_a_long_malformed_value_is_shown_shortened():
    value = "[" + "x" * 500

    with pytest.raises(ValueError, match="is invalid") as exc_info:
        SidecarConfig.parse_url_list(value)

    assert f"Got: {value[:200]}...\n" in str(exc_info.value)


@pytest.mark.parametrize("env_value", ['{"url": "http://a"}', "[1, [", '["http://a", ["nested"]]', "['http://a']"])
def test_json_that_is_not_a_list_of_urls_stops_startup(env_value: str):
    result = _load_in_fresh_interpreter(env_value)

    assert result.returncode != 0
    assert f"PDP_{SETTING} is invalid: " in result.stderr
    assert "Set it to one of:" in result.stderr


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


@pytest.fixture
def logged():
    """INFO and above, as 'LEVEL|message' lines."""
    lines: list[str] = []
    handler_id = logger.add(lines.append, format="{level}|{message}", level="INFO")
    yield lines
    logger.remove(handler_id)


def test_a_malformed_control_plane_override_keeps_the_current_value_and_says_why(monkeypatch, logged):
    monkeypatch.setattr(sidecar_config, SETTING, [CACHE_REBUILD])

    apply_config({SETTING: "['http://a/cb']"}, sidecar_config)

    assert getattr(sidecar_config, SETTING) == [CACHE_REBUILD]
    warning = next(line for line in logged if line.startswith("WARNING|"))
    assert f"PDP_{SETTING} from the control-plane overrides; keeping its current value" in warning


def _remove_ignored(monkeypatch, ignored: list[str], registered: list[str]) -> list[str]:
    """Run the PDP's removal step over a real callbacks register; return the URLs left."""
    monkeypatch.setattr(sidecar_config, SETTING, ignored)
    register = CallbacksRegister()
    for url in registered:
        register.put(url)
    pdp = SimpleNamespace(_opal=SimpleNamespace(_callbacks_register=register))
    PermitPDP._remove_ignored_default_callbacks_urls(pdp)  # ty: ignore[invalid-argument-type]  # needs only _opal
    return sorted(callback.url for callback in register.all())


def test_an_exact_url_drops_its_callback_without_a_warning(monkeypatch, logged):
    remaining = _remove_ignored(monkeypatch, [CACHE_REBUILD], [CACHE_REBUILD, "http://opal/data/callback_report"])

    assert remaining == ["http://opal/data/callback_report"]
    assert not [line for line in logged if line.startswith("WARNING|")]


@pytest.mark.parametrize(
    "near_miss",
    [
        pytest.param(CACHE_REBUILD + "/", id="trailing-slash"),
        pytest.param(CACHE_REBUILD + "?force=1", id="query-string"),
        pytest.param(CACHE_REBUILD.replace("localhost", "LOCALHOST"), id="case"),
        pytest.param("http://localhost:8181/v1/data/permit/rebac", id="prefix"),
    ],
)
def test_a_near_miss_keeps_the_callback_and_warns_with_the_url_to_use(monkeypatch, logged, near_miss: str):
    remaining = _remove_ignored(monkeypatch, [near_miss], [CACHE_REBUILD])

    assert remaining == [CACHE_REBUILD]
    warnings = [line for line in logged if line.startswith("WARNING|")]
    assert len(warnings) == 1
    assert f"PDP_{SETTING} lists {near_miss!r}" in warnings[0]
    assert f"Did you mean {CACHE_REBUILD!r}?" in warnings[0]
    assert "must all match" in warnings[0]


def test_an_unrelated_url_is_only_noted_at_info(monkeypatch, logged):
    remaining = _remove_ignored(monkeypatch, ["http://elsewhere/cb"], [CACHE_REBUILD])

    assert remaining == [CACHE_REBUILD]
    assert not [line for line in logged if line.startswith("WARNING|")]
    info = [line for line in logged if "matches no registered data-update callback" in line]
    assert len(info) == 1
    assert info[0].startswith("INFO|")
    assert CACHE_REBUILD in info[0]
