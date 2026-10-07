"""Which mapping rule /allowed_url picks for a request URL."""

import pytest
from pydantic import AnyHttpUrl, parse_obj_as

from horizon.enforcer.schemas import MappingRuleData, UrlTypes
from horizon.enforcer.utils.mapping_rules_utils import ConflictingQueryParameterError, MappingRulesUtils

BASE = "https://api.example.com/documents"


def _matches(rule_url: str, request_url: str, url_type: UrlTypes = UrlTypes.DEFAULT) -> bool:
    rule = MappingRuleData(url=rule_url, http_method="get", resource="document", action="read", url_type=url_type)
    url = parse_obj_as(AnyHttpUrl, request_url)  # what UrlAuthorizationQuery.url holds
    return MappingRulesUtils.extract_mapping_rule_by_request([rule], "GET", url) is rule


@pytest.mark.parametrize("request_url", [BASE, BASE + "?team=a"], ids=["no-query", "query"])
@pytest.mark.parametrize(
    ("rule_url", "url_type"),
    [
        # Each of the first three makes urllib.parse.urlsplit raise ValueError.
        ("https://[api.example.com/documents", UrlTypes.DEFAULT),
        ("http://[::1", UrlTypes.DEFAULT),
        ("https://api.example\uff0fcom/documents", UrlTypes.DEFAULT),  # NFKC turns U+FF0F into "/"
        ("%%%", UrlTypes.DEFAULT),
        ("?&&==", UrlTypes.DEFAULT),
        (BASE + "?%%%=&&=%zz", UrlTypes.DEFAULT),
        ("https://api.example.com/\x00documents", UrlTypes.DEFAULT),
        ("https://api.exämple.com/döcuments", UrlTypes.DEFAULT),
        ("", UrlTypes.DEFAULT),
        ("[", UrlTypes.REGEX),
        ("(?P<", UrlTypes.REGEX),
    ],
)
def test_a_malformed_rule_url_matches_nothing_and_raises_nothing(rule_url: str, url_type: UrlTypes, request_url: str):
    """Mapping rules come from OPA data. One malformed rule URL must not make every /allowed_url
    request with its method fail; it matches no request instead."""
    assert not _matches(rule_url, request_url, url_type)


@pytest.mark.parametrize(
    ("rule_query", "request_query"),
    [
        ("", ""),
        ("", "?team=a"),
        ("?team=a", "?team=a"),
        ("?team=a", "?team=a&page=2"),
        ("?team={team}", "?team=anything"),
    ],
    ids=["neither", "only-the-request", "equal", "request-adds-params", "attribute-takes-any-value"],
)
def test_a_request_matches_a_rule_whose_query_it_satisfies(rule_query: str, request_query: str):
    assert _matches(BASE + rule_query, BASE + request_query)


@pytest.mark.parametrize(
    ("rule_query", "request_query"),
    [
        ("?team=a", ""),
        ("?team=a", "?team=b"),
        ("?team=a", "?page=2"),
        ("?team={team}", "?page=2"),
    ],
    ids=["request-has-no-query", "different-value", "missing-param", "missing-attribute-param"],
)
def test_a_request_does_not_match_a_rule_whose_query_it_lacks(rule_query: str, request_query: str):
    assert not _matches(BASE + rule_query, BASE + request_query)


@pytest.mark.parametrize(
    ("rule_query", "request_query"),
    [
        ("?id=1", "?id=1&id=1"),
        ("?id=1", "?id=%31&id=1"),
        ("?id={id}", "?id=7&id=7"),
        ("?id=1", "?id=1&page=2&page=3"),
        ("", "?id=1&id=2"),
    ],
    ids=[
        "literal-repeated-same-value",
        "literal-same-value-once-decoded",
        "attribute-repeated-same-value",
        "repeated-param-the-rule-does-not-read",
        "rule-reads-no-query",
    ],
)
def test_a_query_parameter_repeated_with_one_value_matches_as_if_given_once(rule_query: str, request_query: str):
    assert _matches(BASE + rule_query, BASE + request_query)


@pytest.mark.parametrize(
    ("rule_query", "request_query"),
    [
        ("?id=1", "?id=2&id=1"),
        ("?id=1", "?id=1&id=2"),
        ("?id=1", "?id=1&id="),
        ("?id={id}", "?id=1&id=2"),
        ("?team=a&id=1", "?team=a&id=1&id=2"),
    ],
    ids=["last-value-is-the-rules", "first-value-is-the-rules", "other-value-blank", "attribute", "with-other-params"],
)
def test_a_rule_reading_a_query_parameter_with_conflicting_values_raises(rule_query: str, request_query: str):
    """Before PER-16927 the last value decided: ?id=2&id=1 matched a rule on id=1 and ?id=1&id=2 did not.
    An app reading the first value would then act on a different id than the one the PDP checked."""
    with pytest.raises(ConflictingQueryParameterError) as raised:
        _matches(BASE + rule_query, BASE + request_query)
    assert raised.value.key == "id"


@pytest.mark.parametrize(
    ("rule_query", "request_query"),
    [
        ("?id=3", "?id=1&id=2"),
        ("?team=a&id=1", "?team=b&id=1&id=2"),
        ("?team=a&id={id}", "?id=1&id=2"),
    ],
    ids=["no-value-is-the-rules", "another-param-differs", "another-param-missing"],
)
def test_a_rule_no_value_could_satisfy_does_not_match_even_with_conflicting_values(rule_query: str, request_query: str):
    assert not _matches(BASE + rule_query, BASE + request_query)


def _rule(url: str, priority: int | None = None) -> MappingRuleData:
    return MappingRuleData(url=url, http_method="get", resource="document", action="read", priority=priority)


@pytest.mark.parametrize("request_query", ["?admin=true&admin=false", "?admin=false&admin=true"])
def test_conflicting_values_do_not_fall_through_to_a_rule_that_ignores_the_parameter(request_query: str):
    """Skipping only the rule on ?admin=true would hand the request to the catch-all rule, whatever
    value the app goes on to read."""
    rules = [_rule(BASE + "?admin=true", priority=10), _rule(BASE, priority=1)]
    url = parse_obj_as(AnyHttpUrl, BASE + request_query)

    with pytest.raises(ConflictingQueryParameterError):
        MappingRulesUtils.extract_mapping_rule_by_request(rules, "GET", url)


def test_conflicting_values_matter_only_for_rules_on_the_requested_path():
    rules = [_rule("https://api.example.com/other?id=1"), _rule(BASE)]
    url = parse_obj_as(AnyHttpUrl, BASE + "?id=1&id=2")

    assert MappingRulesUtils.extract_mapping_rule_by_request(rules, "GET", url) is rules[1]


@pytest.mark.parametrize(
    ("rule_url", "request_url", "expected"),
    [
        (BASE + "?id={doc_id}", BASE + "?id=7", {"doc_id": "7"}),
        (BASE + "?id={doc_id}", BASE + "?id=7&id=7", {"doc_id": "7"}),
        (BASE + "?id={doc_id}", BASE + "?id=7&page=1&page=2", {"doc_id": "7"}),
        (BASE + "?id=7", BASE + "?id=7&id=8", {}),
        (BASE, BASE + "?id=7&id=8", {}),
        (BASE + "?id={doc_id}", BASE, {}),
    ],
    ids=[
        "single",
        "repeated-same-value",
        "repeated-param-the-rule-does-not-read",
        "rule-reads-no-attribute",
        "rule-without-query",
        "request-without-query",
    ],
)
def test_query_attributes_come_from_the_parameters_value(rule_url: str, request_url: str, expected: dict):
    assert MappingRulesUtils.extract_attributes_from_query_params(rule_url, request_url) == expected


@pytest.mark.parametrize("request_query", ["?id=7&id=8", "?id=8&id=7", "?id=7&id="])
def test_query_attributes_raise_for_a_parameter_with_conflicting_values(request_query: str):
    with pytest.raises(ConflictingQueryParameterError) as raised:
        MappingRulesUtils.extract_attributes_from_query_params(BASE + "?id={doc_id}", BASE + request_query)
    assert raised.value.key == "id"
