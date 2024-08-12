from permit_datafilter.compile_api.schemas import CompileResponse
from permit_datafilter.rego_ast import parser as ast
from permit_datafilter.boolean_expression.schemas import (
    ResidualPolicyResponse,
    ResidualPolicyType,
)
from permit_datafilter.boolean_expression.translator import (
    translate_opa_queryset,
)


def test_ast_to_boolean_expr():
    response = CompileResponse(
        **{
            "result": {
                "queries": [
                    [
                        {
                            "index": 0,
                            "terms": [
                                {
                                    "type": "ref",
                                    "value": [{"type": "var", "value": "eq"}],
                                },
                                {
                                    "type": "ref",
                                    "value": [
                                        {"type": "var", "value": "input"},
                                        {"type": "string", "value": "resource"},
                                        {"type": "string", "value": "tenant"},
                                    ],
                                },
                                {"type": "string", "value": "default"},
                            ],
                        }
                    ],
                    [
                        {
                            "index": 0,
                            "terms": [
                                {
                                    "type": "ref",
                                    "value": [{"type": "var", "value": "eq"}],
                                },
                                {
                                    "type": "ref",
                                    "value": [
                                        {"type": "var", "value": "input"},
                                        {"type": "string", "value": "resource"},
                                        {"type": "string", "value": "tenant"},
                                    ],
                                },
                                {"type": "string", "value": "second"},
                            ],
                        }
                    ],
                ]
            }
        }
    )
    queryset = ast.QuerySet.parse(response)
    residual_policy: ResidualPolicyResponse = translate_opa_queryset(queryset)
    # print(json.dumps(residual_policy.dict(), indent=2))

    assert residual_policy.type == ResidualPolicyType.CONDITIONAL
    assert residual_policy.condition.expression.operator == "or"
    assert len(residual_policy.condition.expression.operands) == 2

    assert residual_policy.condition.expression.operands[0].expression.operator == "eq"
    assert (
        residual_policy.condition.expression.operands[0].expression.operands[0].variable
        == "input.resource.tenant"
    )
    assert (
        residual_policy.condition.expression.operands[0].expression.operands[1].value
        == "default"
    )
