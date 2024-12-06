from pydantic import AnyHttpUrl
from starlette.datastructures import QueryParams
import re
from urllib.parse import urlparse
from typing import List, Optional

from horizon.enforcer.schemas import MappingRuleData
from opal_client.logger import logger


class MappingRulesUtils:
    @staticmethod
    def _compare_urls(mapping_rule_url: AnyHttpUrl, request_url: AnyHttpUrl) -> bool:
        if mapping_rule_url.scheme != request_url.scheme:
            return False
        if mapping_rule_url.host != request_url.host:
            return False
        if not MappingRulesUtils._compare_url_path(
            mapping_rule_url.path, request_url.path
        ):
            return False
        if not MappingRulesUtils._compare_query_params(
            mapping_rule_url.query, request_url.query
        ):
            return False
        return True

    @staticmethod
    def _compare_url_path(
        mapping_rule_url: str | None, request_url: str | None
    ) -> bool:
        if mapping_rule_url is None or request_url is None:
            return mapping_rule_url is None and request_url is None

        mapping_rule_url_parts = mapping_rule_url.split("/")
        request_url_parts = request_url.split("/")
        
        if len(mapping_rule_url_parts) != len(request_url_parts):
            return False
            
        return all(
            part.startswith("{") and part.endswith("}") or part == req_part
            for part, req_part in zip(mapping_rule_url_parts, request_url_parts)
        )

    @staticmethod
    def _compare_query_params(
        mapping_rule_query_string: str | None, request_url_query_string: str | None
    ) -> bool:
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

            if mapping_rule_query_params[key].startswith(
                "{"
            ) and mapping_rule_query_params[key].endswith("}"):
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
        
        if len(rule_url_parts) != len(request_url_parts):
            return {}
            
        return {
            rule_part[1:-1]: req_part
            for rule_part, req_part in zip(rule_url_parts, request_url_parts)
            if rule_part.startswith("{") and rule_part.endswith("}")
        }

    @staticmethod
    def extract_attributes_from_query_params(rule_url: str, request_url: str) -> dict:
        if "?" not in rule_url or "?" not in request_url:
            return {}
        rule_query_params = QueryParams(rule_url.split("?")[1])
        request_query_params = QueryParams(request_url.split("?")[1])
        attributes = {}
        for key in rule_query_params.keys():
            if rule_query_params[key].startswith("{") and rule_query_params[
                key
            ].endswith("}"):
                attributes[rule_query_params[key][1:-1]] = request_query_params[key]
        return attributes

    @classmethod
    def _compare_urls(
        cls, 
        mapping_rule_url: str, 
        request_url: str, 
        is_regex: bool = False
    ) -> bool:
        """
        Compare a mapping rule URL against a request URL.
        """
        # If the mapping rule is a regex pattern
        if is_regex:
            try:
                pattern = re.compile(mapping_rule_url)
                match_result = bool(pattern.match(request_url))
                logger.debug(
                    "regex url comparison",
                    pattern=mapping_rule_url,
                    url=request_url,
                    matched=match_result
                )
                return match_result
            except re.error as e:
                logger.warning(
                    "regex pattern compilation failed",
                    pattern=mapping_rule_url,
                    error=str(e)
                )
                return False
            
        # Otherwise use the traditional URL comparison logic
        try:
            mapping_url = urlparse(mapping_rule_url)
            req_url = urlparse(request_url)
            
            if mapping_url.scheme and mapping_url.scheme != req_url.scheme:
                return False
            
            if mapping_url.netloc and mapping_url.netloc != req_url.netloc:
                return False
            
            # Compare paths using the existing template matching logic
            return cls._match_url_template(mapping_url.path, req_url.path)
        except Exception:
            return False

    @classmethod
    def extract_mapping_rule_by_request(
        cls, 
        mapping_rules: List[MappingRuleData], 
        http_method: str, 
        url: str
    ) -> Optional[MappingRuleData]:
        """Extract matching mapping rule for the given request"""
        http_method = http_method.lower()  # Convert once instead of in each iteration
        
        for mapping_rule in mapping_rules:
            is_regex = getattr(mapping_rule, 'type', None) == "regex"
            
            logger.debug(
                "checking mapping rule",
                rule_url=mapping_rule.url,
                rule_method=mapping_rule.http_method,
                rule_type=getattr(mapping_rule, 'type', None),
                request_url=url,
                request_method=http_method,
                is_regex=is_regex
            )
            
            # Check method first as it's cheaper than URL comparison
            if mapping_rule.http_method.lower() != http_method:
                continue
                
            if not cls._compare_urls(mapping_rule.url, url, is_regex=is_regex):
                continue
            
            logger.debug("found matching rule")
            return mapping_rule
        
        return None
