from pydantic import AnyHttpUrl
from starlette.datastructures import QueryParams

from horizon.enforcer.schemas import MappingRuleData


class MappingRulesUtils:
    @staticmethod
    def _compare_urls(mapping_rule_url: AnyHttpUrl, request_url: AnyHttpUrl) -> bool:
        if mapping_rule_url.scheme != request_url.scheme:
            return False
        if mapping_rule_url.host != request_url.host:
            return False
        if not MappingRulesUtils._compare_url_path(mapping_rule_url.path, request_url.path):
            return False
        if not MappingRulesUtils._compare_query_params(mapping_rule_url.query, request_url.query):
            return False
        return True

    @staticmethod
    def _compare_url_path(mapping_rule_url: str | None, request_url: str | None) -> bool:
        if mapping_rule_url is None and request_url is None:
            return True
        if not (mapping_rule_url is not None and request_url is not None):
            return False
        mapping_rule_url_parts = mapping_rule_url.split("/")
        request_url_parts = request_url.split("/")
        if len(mapping_rule_url_parts) != len(request_url_parts):
            return False
        for i in range(len(mapping_rule_url_parts)):
            if mapping_rule_url_parts[i].startswith("{") and mapping_rule_url_parts[i].endswith("}"):
                continue
            if mapping_rule_url_parts[i] != request_url_parts[i]:
                return False
        return True

    @staticmethod
    def _compare_query_params(mapping_rule_query_string: str | None, request_url_query_string: str | None) -> bool:
        if mapping_rule_query_string is None and request_url_query_string is None:
            # if both are None, they are equal
            return True
        if mapping_rule_query_string is not None and request_url_query_string is None:
            # if the request query string is None, but the mapping rule query string is not
            # then the request does not match the mapping rule
            return False
        if mapping_rule_query_string is None and request_url_query_string is not None:
            # if the mapping rule query string is None, but the request query string is not
            # then the request matches the query string rules it has additional data to the rule
            return True

        mapping_rule_query_params = QueryParams(mapping_rule_query_string)
        request_query_params = QueryParams(request_url_query_string)

        for key in mapping_rule_query_params.keys():
            if key not in request_query_params:
                return False

            if mapping_rule_query_params[key].startswith("{") and mapping_rule_query_params[key].endswith("}"):
                # if the value is an attribute
                # we just need to make sure the attribute is in the request query params
                continue
            elif mapping_rule_query_params[key] != request_query_params[key]:
                # if the value is not an attribute, verify that the values are the same
                return False
        return True

    @staticmethod
    def extract_attributes_from_url(rule_url: str, request_url: str) -> dict:
        rule_url_parts = rule_url.split("/")
        request_url_parts = request_url.split("/")
        attributes = {}
        if len(rule_url_parts) != len(request_url_parts):
            return {}
        for i in range(len(rule_url_parts)):
            if rule_url_parts[i].startswith("{") and rule_url_parts[i].endswith("}"):
                attributes[rule_url_parts[i][1:-1]] = request_url_parts[i]
        return attributes

    @staticmethod
    def extract_attributes_from_query_params(rule_url: str, request_url: str) -> dict:
        if "?" not in rule_url or "?" not in request_url:
            return {}
        rule_query_params = QueryParams(rule_url.split("?")[1])
        request_query_params = QueryParams(request_url.split("?")[1])
        attributes = {}
        for key in rule_query_params.keys():
            if rule_query_params[key].startswith("{") and rule_query_params[key].endswith("}"):
                attributes[rule_query_params[key][1:-1]] = request_query_params[key]
        return attributes

    @classmethod
    def extract_mapping_rule_by_request(
        cls,
        mapping_rules: list[MappingRuleData],
        http_method: str,
        url: AnyHttpUrl,
    ) -> MappingRuleData | None:
        matched_mapping_rules = []
        for mapping_rule in mapping_rules:
            if mapping_rule.http_method != http_method.lower():
                # if the method is not the same, we don't need to check the url
                continue
            if not cls._compare_urls(mapping_rule.url, url):
                # if the urls doesn't match, we don't need to check the headers
                continue
            matched_mapping_rules.append(mapping_rule)
        # most priority first
        matched_mapping_rules.sort(key=lambda rule: rule.priority or 0, reverse=True)
        if len(matched_mapping_rules) > 0:
            return matched_mapping_rules[0]

        return None
