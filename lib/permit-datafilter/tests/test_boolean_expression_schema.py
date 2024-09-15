import pytest
import pydantic

from permit_datafilter.boolean_expression.schemas import (
    ResidualPolicyResponse,
    ResidualPolicyType,
)


def test_valid_residual_policies():
    d = {
        "type": "conditional",
        "condition": {
            "expression": {
                "operator": "or",
                "operands": [
                    {
                        "expression": {
                            "operator": "eq",
                            "operands": [
                                {"variable": "input.resource.tenant"},
                                {"value": "default"},
                            ],
                        }
                    },
                    {
                        "expression": {
                            "operator": "eq",
                            "operands": [
                                {"variable": "input.resource.tenant"},
                                {"value": "second"},
                            ],
                        }
                    },
                ],
            }
        },
    }
    policy = ResidualPolicyResponse(**d)
    assert policy.type == ResidualPolicyType.CONDITIONAL
    assert policy.condition.expression.operator == "or"
    assert len(policy.condition.expression.operands) == 2

    d = {"type": "always_allow", "condition": None}
    policy = ResidualPolicyResponse(**d)
    assert policy.type == ResidualPolicyType.ALWAYS_ALLOW
    assert policy.condition == None

    d = {"type": "always_deny", "condition": None}
    policy = ResidualPolicyResponse(**d)
    assert policy.type == ResidualPolicyType.ALWAYS_DENY
    assert policy.condition == None


def test_invalid_residual_policies():
    for trival_residual_type in ["always_allow", "always_deny"]:
        d = {
            "type": trival_residual_type,
            "condition": {
                "expression": {
                    "operator": "or",
                    "operands": [
                        {
                            "expression": {
                                "operator": "eq",
                                "operands": [
                                    {"variable": "input.resource.tenant"},
                                    {"value": "default"},
                                ],
                            }
                        },
                        {
                            "expression": {
                                "operator": "eq",
                                "operands": [
                                    {"variable": "input.resource.tenant"},
                                    {"value": "second"},
                                ],
                            }
                        },
                    ],
                }
            },
        }
        with pytest.raises(pydantic.ValidationError) as e:
            policy = ResidualPolicyResponse(**d)
        assert "invalid residual policy" in str(e.value)

    d = {"type": "conditional", "condition": None}
    with pytest.raises(pydantic.ValidationError) as e:
        policy = ResidualPolicyResponse(**d)
    assert "invalid residual policy" in str(e.value)
