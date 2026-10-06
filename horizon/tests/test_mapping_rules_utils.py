"""Which mapping rule /allowed_url picks for a request URL, by its query string."""

import pytest
from pydantic import AnyHttpUrl, parse_obj_as

from horizon.enforcer.schemas import MappingRuleData
from horizon.enforcer.utils.mapping_rules_utils import MappingRulesUtils

BASE = "https://api.example.com/documents"


def _matches(rule_url: str, request_url: str) -> bool:
    rule = MappingRuleData(url=rule_url, http_method="get", resource="document", action="read")
    url = parse_obj_as(AnyHttpUrl, request_url)  # what UrlAuthorizationQuery.url holds
    return MappingRulesUtils.extract_mapping_rule_by_request([rule], "GET", url) is rule


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
