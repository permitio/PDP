import re2 as re  # use re2 instead of re for regex matching because it's simiplier and safer for user inputted regexes
from loguru import logger
from pydantic import AnyHttpUrl
from starlette.datastructures import QueryParams

from horizon.enforcer.schemas import MappingRuleData, UrlTypes


class MappingRulesUtils:
    @staticmethod
    def _compare_httpurls(mapping_rule_url: AnyHttpUrl, request_url: AnyHttpUrl) -> bool:
        if mapping_rule_url.scheme != request_url.scheme:
            return False
        if mapping_rule_url.host != request_url.host:
            return False
        if not MappingRulesUtils._compare_url_path(mapping_rule_url.path, request_url.path):
            return False
        if not MappingRulesUtils._compare_query_params(mapping_rule_url.query, request_url.query):  # noqa: SIM103
            return False
        return True

    @staticmethod
    def _compare_url_path(mapping_rule_url: str | None, request_url: str | None) -> bool:
        if mapping_rule_url is None or request_url is None:
            return mapping_rule_url is None and request_url is None

        mapping_rule_url_parts = mapping_rule_url.split("/")
        request_url_parts = request_url.split("/")

        if len(mapping_rule_url_parts) != len(request_url_parts):
            return False

        return all(
            (part.startswith("{") and part.endswith("}")) or part == req_part
            for part, req_part in zip(mapping_rule_url_parts, request_url_parts, strict=False)
        )

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

        mapping_rule_query_params = QueryParams(mapping_rule_query_string or "")
        request_query_params = QueryParams(request_url_query_string or "")

        for key in mapping_rule_query_params:
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
        for key in rule_query_params:
            if rule_query_params[key].startswith("{") and rule_query_params[key].endswith("}"):
                attributes[rule_query_params[key][1:-1]] = request_query_params[key]
        return attributes

    @classmethod
    def _compare_urls(cls, mapping_rule_url: str, request_url: str, *, is_regex: bool = False) -> bool:
        """
        Compare a mapping rule URL against a request URL.
        """
        # If the mapping rule is a regex pattern
        if is_regex:
            try:
                pattern = re.compile(mapping_rule_url)
                match_result = bool(pattern.match(request_url))
                logger.debug("regex url comparison", pattern=mapping_rule_url, url=request_url, matched=match_result)
                return match_result
            except re.error as e:
                logger.warning("regex pattern compilation failed", pattern=mapping_rule_url, error=str(e))
                return False

        # For traditional URL matching
        try:
            # Split URL into path and query parts
            mapping_rule_parts = mapping_rule_url.split("?", 1)
            request_parts = request_url.split("?", 1)

            # Compare paths
            if not cls._compare_url_path(mapping_rule_parts[0], request_parts[0]):
                return False

            # Compare query parameters if they exist
            if len(mapping_rule_parts) > 1 and len(request_parts) > 1:
                return cls._compare_query_params(mapping_rule_parts[1], request_parts[1])
            # If mapping rule has query params but request doesn't, return False
            elif len(mapping_rule_parts) > 1:
                return False
            # If request has query params but mapping rule doesn't, that's okay
            return True

        except Exception as e:  # noqa: BLE001
            logger.warning(
                "URL comparison failed - verify URL format and structure",
                mapping_url=mapping_rule_url,
                request_url=request_url,
                error_message=str(e),
                error_type=type(e).__name__,
            )
            return False

    @classmethod
    def extract_mapping_rule_by_request(
        cls,
        mapping_rules: list[MappingRuleData],
        http_method: str,
        url: AnyHttpUrl,
    ) -> MappingRuleData | None:
        matched_mapping_rules = []
        http_method = http_method.lower()  # Convert once instead of in each iteration

        for mapping_rule in mapping_rules:
            is_regex = mapping_rule.url_type == UrlTypes.REGEX

            logger.debug(
                "checking mapping rule",
                rule_url=mapping_rule.url,
                rule_method=mapping_rule.http_method,
                rule_type=getattr(mapping_rule, "url_type", None),
                request_url=url,
                request_method=http_method,
                is_regex=is_regex,
            )

            # Check method first as it's cheaper than URL comparison
            if mapping_rule.http_method.lower() != http_method:
                # if the method is not the same, we don't need to check the url
                continue

            if not cls._compare_urls(mapping_rule.url, url, is_regex=is_regex):
                continue

            matched_mapping_rules.append(mapping_rule)

        # most priority first
        matched_mapping_rules.sort(key=lambda rule: rule.priority or 0, reverse=True)
        if len(matched_mapping_rules) > 0:
            return matched_mapping_rules[0]

        return None
