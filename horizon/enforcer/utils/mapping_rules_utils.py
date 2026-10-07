# TODO: change to use re2 in the future, currently not supported in alpine due to c++ library issues
# import re2 as re  # use re2 instead of re for regex matching because it's simiplier and safer for user inputted regexes  # noqa: ERA001,E501
import re

from loguru import logger
from pydantic import AnyHttpUrl
from starlette.datastructures import QueryParams

from horizon.enforcer.schemas import MappingRuleData, UrlTypes


class ConflictingQueryParameterError(ValueError):
    """A query parameter a mapping rule reads has more than one distinct value in the requested URL.

    Which value the protected app reads for such a parameter is up to the app, so the PDP cannot
    tell which rule applies or which attribute value to check.
    """

    def __init__(self, key: str):
        super().__init__(f"Query parameter '{key}' has more than one distinct value in the requested URL")
        self.key = key


class MappingRulesUtils:
    @staticmethod
    def _compare_httpurls(mapping_rule_url: str, request_url: str) -> bool:
        # Split URL into path and query parts
        mapping_rule_parts = mapping_rule_url.split("?", 1)
        request_parts = request_url.split("?", 1)
        if not MappingRulesUtils._compare_url_path(mapping_rule_parts[0], request_parts[0]):
            return False
        # Compare query parameters if they exist
        if len(mapping_rule_parts) > 1 and len(request_parts) > 1:
            return MappingRulesUtils._compare_query_params(mapping_rule_parts[1], request_parts[1])
        return len(mapping_rule_parts) <= 1

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
    def _compare_query_params(mapping_rule_query_string: str, request_url_query_string: str) -> bool:
        """Whether the request's query satisfies every parameter of the mapping rule's query.

        A parameter repeated with one value counts as given once.

        Raises:
            ConflictingQueryParameterError: the request could satisfy the rule, but a parameter the
                rule reads has more than one distinct value, so whether it does depends on the value read.
        """
        mapping_rule_query_params = QueryParams(mapping_rule_query_string)
        request_query_params = QueryParams(request_url_query_string)
        conflicting_key = None

        for key in mapping_rule_query_params:
            request_values = set(request_query_params.getlist(key))
            if not request_values:
                return False

            rule_value = mapping_rule_query_params[key]
            is_attribute = rule_value.startswith("{") and rule_value.endswith("}")
            if not is_attribute and rule_value not in request_values:
                return False
            if len(request_values) > 1:
                conflicting_key = key

        if conflicting_key is not None:
            raise ConflictingQueryParameterError(conflicting_key)
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
        """The attributes a mapping rule's query reads from the request URL, e.g. ``{"id": "7"}`` for
        a rule with ``?id={id}`` and a request with ``?id=7``.

        Raises:
            ConflictingQueryParameterError: a parameter the rule reads an attribute from has more than
                one distinct value in the request URL.
        """
        if "?" not in rule_url or "?" not in request_url:
            return {}
        rule_query_params = QueryParams(rule_url.split("?", 1)[1])
        request_query_params = QueryParams(request_url.split("?", 1)[1])
        attributes = {}
        for key in rule_query_params:
            if rule_query_params[key].startswith("{") and rule_query_params[key].endswith("}"):
                if len(set(request_query_params.getlist(key))) > 1:
                    raise ConflictingQueryParameterError(key)
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
            except re.error as e:
                logger.warning("regex pattern compilation failed", pattern=mapping_rule_url, error=str(e))
                return False
            match_result = bool(pattern.match(request_url))
            logger.debug("regex url comparison", pattern=mapping_rule_url, url=request_url, matched=match_result)
            return match_result

        return cls._compare_httpurls(mapping_rule_url, request_url)

    @classmethod
    def extract_mapping_rule_by_request(
        cls,
        mapping_rules: list[MappingRuleData],
        http_method: str,
        url: AnyHttpUrl,
    ) -> MappingRuleData | None:
        """The highest-priority mapping rule for the request's method and URL, or None if none matches.

        Rules of equal priority keep their order in ``mapping_rules``.

        Raises:
            ConflictingQueryParameterError: the rule that would come first could match, but a query
                parameter it reads has more than one distinct value. The request then gets no rule at
                all, rather than a lower-priority one that skips the parameter. A conflict in a rule
                that a matching rule outranks does not matter: that rule comes first whatever value
                is read.
        """
        candidates: list[tuple[MappingRuleData, ConflictingQueryParameterError | None]] = []
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

            try:
                if not cls._compare_urls(mapping_rule.url, url, is_regex=is_regex):
                    continue
            except ConflictingQueryParameterError as conflict:
                candidates.append((mapping_rule, conflict))
            else:
                candidates.append((mapping_rule, None))

        if not candidates:
            return None
        # most priority first; the sort is stable, so equal priorities keep the rules' order
        candidates.sort(key=lambda candidate: candidate[0].priority or 0, reverse=True)
        first_rule, conflict = candidates[0]
        if conflict is not None:
            raise conflict
        return first_rule
