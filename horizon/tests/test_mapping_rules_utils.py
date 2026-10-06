"""Which mapping rule /allowed_url picks for a request URL."""

import pytest
from pydantic import AnyHttpUrl, parse_obj_as

from horizon.enforcer.schemas import MappingRuleData, UrlTypes
from horizon.enforcer.utils.mapping_rules_utils import MappingRulesUtils

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
