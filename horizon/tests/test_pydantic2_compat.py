"""Behaviour the PDP had on pydantic 1 and keeps on pydantic 2 (PER-16197).

Each test names a difference between the two that would otherwise reach a caller: a request that
used to succeed, an OPA result that used to parse, a file an older PDP wrote. The fixtures under
fixtures/ were written by the pydantic 1 code (PDP main before PER-16197), not by hand.
"""

import json
import uuid
from pathlib import Path

import pytest
from pydantic import ValidationError

from horizon.config import SidecarConfig
from horizon.enforcer.schemas import (
    AuthorizationQuery,
    AuthorizationResult,
    AuthorizedUsersAuthorizationQuery,
    MappingRuleData,
    UrlAuthorizationQuery,
    _UserPermissionsResult,
)
from horizon.enforcer.schemas_kong import KongAuthorizationInput
from horizon.local.schemas import (
    ListRoleAssignmentsFilters,
    ListRoleAssignmentsPagination,
    ListRoleAssignmentsPDPBody,
    SyncedRole,
    SyncedUser,
)
from horizon.startup.offline_mode import OfflineModeManager
from horizon.state import PersistentState

FIXTURES = Path(__file__).with_name("fixtures")
FIXTURE_API_KEY = "permit_key_fixture-not-a-real-key"  # the key the backup fixture was written with


# --------------------------------------------------------------------------- request bodies


def test_numeric_keys_are_still_accepted_as_strings():
    """pydantic 1 turned a number in a str field into its string; pydantic 2 answers 422 unless
    coerce_numbers_to_str is set. SDKs that send numeric user or resource keys keep working."""
    query = AuthorizationQuery.model_validate(
        {"user": {"key": 1}, "action": 2, "resource": {"type": 3, "key": 4.5, "tenant": 6}}
    )
    assert (query.user.key, query.action, query.resource.type) == ("1", "2", "3")
    assert (query.resource.key, query.resource.tenant) == ("4.5", "6")


def test_camel_case_aliases_and_field_names_both_populate():
    by_alias = AuthorizationQuery.model_validate(
        {"user": {"key": "u", "firstName": "A", "lastName": "B"}, "action": "read", "resource": {"type": "doc"}}
    )
    by_name = AuthorizationQuery.model_validate(
        {"user": {"key": "u", "first_name": "A", "last_name": "B"}, "action": "read", "resource": {"type": "doc"}}
    )
    assert by_alias.user.first_name == by_name.user.first_name == "A"
    # What the PDP sends OPA: field names, as pydantic 1's .dict() did.
    assert by_alias.model_dump()["user"]["first_name"] == "A"


def test_optional_request_fields_stay_optional():
    """A bare `X | None` annotation was optional on pydantic 1 and is required on pydantic 2."""
    assert AuthorizedUsersAuthorizationQuery.model_validate({"action": "read", "resource": {"type": "doc"}}).sdk is None


@pytest.mark.parametrize(
    ("body", "check"),
    [
        # An empty map some JSON encoders (PHP's json_encode([])) write as an array.
        ({"user": {"key": "u", "attributes": []}}, lambda q: q.user.attributes == {}),
        ({"resource": {"type": "doc", "attributes": []}}, lambda q: q.resource.attributes == {}),
        ({"context": []}, lambda q: q.context == {}),
        ({"user": {"key": "u", "attributes": [["region", "eu"]]}}, lambda q: q.user.attributes == {"region": "eu"}),
        ({"user": {"key": True}}, lambda q: q.user.key == "True"),
        ({"action": False}, lambda q: q.action == "False"),
    ],
)
def test_request_bodies_pydantic1_accepted_are_still_accepted(body, check):
    """pydantic 1 ran dict() on a list for a dict field and str() on a bool for a str field."""
    base = {"user": {"key": "u"}, "action": "read", "resource": {"type": "doc"}}
    assert check(AuthorizationQuery.model_validate({**base, **body}))


def test_a_dict_field_still_rejects_what_dict_refuses():
    with pytest.raises(ValidationError):
        AuthorizationQuery.model_validate(
            {"user": {"key": "u", "attributes": "x"}, "action": "read", "resource": {"type": "doc"}}
        )


def test_kong_flag_query_parameters_are_accepted():
    """Kong sends `true` for a query parameter with no value (?verbose); pydantic 1 read "True"."""
    http = {"host": "h", "port": 80, "tls": {}, "method": "GET", "scheme": "http", "path": "/", "headers": {}}
    kong = KongAuthorizationInput.model_validate({"request": {"http": {**http, "querystring": {"verbose": True}}}})
    assert kong.request.http.querystring == {"verbose": "True"}


# --------------------------------------------------------------------------- URLs


@pytest.mark.parametrize(
    ("given", "kept"),
    [
        ("https://api.example.com", "https://api.example.com"),
        ("https://api.example.com/docs?a=1&a=2", "https://api.example.com/docs?a=1&a=2"),
        ("  https://api.example.com/docs  ", "https://api.example.com/docs"),
        ("http://localhost:8080/x", "http://localhost:8080/x"),
        # pydantic 1 IDNA-encoded the host and left the path alone.
        ("http://exämple.com/ä", "http://xn--exmple-cua.com/ä"),
    ],
)
def test_allowed_url_keeps_the_callers_url_string(given, kept):
    """pydantic 2's AnyHttpUrl returns a Url object and rewrites the string ("https://h" ->
    "https://h/"), which would change which mapping rule a URL matches. The PDP keeps the string,
    stripped of surrounding whitespace as pydantic 1 did."""
    query = UrlAuthorizationQuery.model_validate(
        {"user": {"key": "u"}, "http_method": "get", "url": given, "tenant": "default"}
    )
    assert query.url == kept
    assert query.model_dump()["url"] == kept
    json.dumps(query.model_dump())  # the OPA input stays JSON-serializable


@pytest.mark.parametrize("bad", ["not a url", "ftp://example.com/x", "", "https://", "http://h/a b"])
def test_allowed_url_still_rejects_what_is_not_an_http_url(bad):
    with pytest.raises(ValidationError):
        UrlAuthorizationQuery.model_validate({"user": {"key": "u"}, "http_method": "get", "url": bad, "tenant": "t"})


# --------------------------------------------------------------------------- OPA results


def test_user_permissions_result_parses_without_tenant_or_resource():
    """OPA can leave either out. Required on pydantic 2 without a default: /user-permissions would
    fall into its fallback and answer {} for a user who has permissions."""
    result = _UserPermissionsResult.model_validate({"permissions": ["document:read"]})
    assert result.tenant is None
    assert result.resource is None


def test_user_permissions_pattern_applies_per_item():
    assert _UserPermissionsResult.model_validate({"permissions": ["document:read", "a:b:c"]}).permissions
    assert _UserPermissionsResult.model_validate({"permissions": []}).permissions == []
    with pytest.raises(ValidationError):
        _UserPermissionsResult.model_validate({"permissions": ["document:read", "no-colon"]})


def test_authorization_result_debug_is_optional():
    assert AuthorizationResult.model_validate({"allow": True}).debug is None


def test_malformed_opa_debug_and_priority_parse_as_on_pydantic1():
    """A list for the debug dict, a fractional priority: pydantic 1 coerced both; pydantic 2 would
    500 /allowed (response validation) and /allowed_url."""
    assert AuthorizationResult.model_validate({"allow": True, "debug": []}).debug == {}
    rule = MappingRuleData.model_validate(
        {"url": "https://h/x", "http_method": "get", "resource": "r", "action": "a", "priority": 1.5}
    )
    assert rule.priority == 1


def test_exclude_none_drops_nulls_inside_dict_fields():
    """FastAPI encoded pydantic 1 responses with jsonable_encoder, which dropped None-valued keys
    at any depth under response_model_exclude_none. pydantic 2 drops only None model fields."""
    result = AuthorizationResult.model_validate(
        {"allow": True, "debug": {"rbac": {"allow": [{"role": "admin", "tenant": None}], "code": None}, "abac": None}}
    )
    assert result.model_dump(mode="json", exclude_none=True) == {
        "allow": True,
        "debug": {"rbac": {"allow": [{"role": "admin"}]}},
        "result": False,
    }
    # Without exclude_none nothing is dropped.
    assert result.model_dump(mode="json")["debug"]["abac"] is None


def test_kong_input_parses_without_the_optional_sections():
    kong = KongAuthorizationInput.model_validate(
        {
            "request": {
                "http": {
                    "host": "h",
                    "port": 80,
                    "tls": {},
                    "method": "GET",
                    "scheme": "http",
                    "path": "/",
                    "querystring": {},
                    "headers": {},
                }
            }
        }
    )
    assert (kong.client_ip, kong.service, kong.route, kong.consumer) == (None, None, None, None)


def test_synced_user_and_role_parse_with_only_the_required_fields():
    user = SyncedUser.model_validate({"id": "u", "roles": [{"id": "r"}]})
    assert user.name is None
    assert user.roles == [SyncedRole(id="r")]


def test_role_assignment_filters_leave_unset_filters_out_of_the_opa_input():
    """The policy reads an absent filter as "no filter"; pydantic 1's code dropped the None ones
    with .dict(exclude_none=True). OPAL 0.10 dumps the input with model_dump(mode="json")."""
    body = ListRoleAssignmentsPDPBody(
        filters=ListRoleAssignmentsFilters(user="u", tenant=None),
        pagination=ListRoleAssignmentsPagination(page=2, per_page=30),
    )
    assert body.model_dump(mode="json") == {"filters": {"user": "u"}, "pagination": {"page": 2, "per_page": 30}}


# --------------------------------------------------------------------------- config


@pytest.mark.parametrize(
    ("raw", "parsed"),
    [
        ('{"permit_graph": {"enabled": false}}', {"permit_graph": {"enabled": False}}),
        ('{"permit_graph": {"enabled": true}}', {"permit_graph": {"enabled": True}}),
        ('{"permit_graph": {"enabled": "false"}}', {"permit_graph": {"enabled": "false"}}),
        ('{"envoy": {"port": "9191"}}', {"envoy": {"port": 9191}}),
        ('{"envoy": {"port": 9191, "path": "a/b"}}', {"envoy": {"port": 9191, "path": "a/b"}}),
        ('{"p": {"t": "t"}}', {"p": {"t": "t"}}),
        # Changed on purpose: pydantic 1 truncated 0.5 to 0 and read "false" as False.
        ('{"p": {"ratio": 0.5}}', {"p": {"ratio": 0.5}}),
        ("{}", {}),
    ],
)
def test_opa_plugin_settings_keep_their_json_types(raw, parsed):
    """JSON bools stay bools (pydantic 1 read them as 0/1 and OPA refused to start); numeric
    strings still become ints, as they did on pydantic 1. Two cases differ from pydantic 1 on
    purpose: "false" stays a string (OPA reads it unquoted, as YAML false; see #402) and a
    fractional number stays a float (pydantic 1 truncated it)."""
    result = SidecarConfig.parse_plugins(raw)
    assert result == parsed
    for settings in result.values():
        for key, value in settings.items():
            assert type(value) is type(parsed[next(iter(parsed))][key])


# --------------------------------------------------------------------------- files an older PDP wrote


def test_offline_mode_restores_a_backup_written_by_the_pydantic1_pdp(tmp_path):
    """An upgraded PDP must read the remote-config backup the previous version left on its volume,
    or offline mode has nothing to start from."""
    backup = tmp_path / "backup.json"
    backup.write_bytes((FIXTURES / "remote_config_backup_pydantic1.json").read_bytes())
    restored = OfflineModeManager(backup, FIXTURE_API_KEY).restore_config()
    assert restored is not None
    assert restored.pdp["OPA_PLUGINS"] == {"permit_graph": {"enabled": False}}
    assert restored.context["note"] == "naïve – non-ASCII ✓"  # noqa: RUF001 - the en dash is the non-ASCII under test


def test_offline_mode_backup_round_trips(tmp_path):
    backup = tmp_path / "backup.json"
    original = OfflineModeManager(backup, FIXTURE_API_KEY)
    source = OfflineModeManager(FIXTURES / "remote_config_backup_pydantic1.json", FIXTURE_API_KEY).restore_config()
    assert source is not None
    original.backup_config(source)
    assert OfflineModeManager(backup, FIXTURE_API_KEY).restore_config() == source
    # Same top-level shape the pydantic 1 PDP writes, so a rollback can still read it.
    assert set(json.loads(backup.read_text())) == {"enc_remote_config", "key_derivation_salt"}


def test_persistent_state_written_by_the_pydantic1_pdp_loads():
    state = PersistentState.model_validate_json((FIXTURES / "persistent_state_pydantic1.json").read_bytes())
    assert state.pdp_instance_id == uuid.UUID("00000000-0000-4000-8000-0000000000aa")
    assert state.seen_sdks == ["python", None]
    assert json.loads(state.model_dump_json()) == json.loads((FIXTURES / "persistent_state_pydantic1.json").read_text())
