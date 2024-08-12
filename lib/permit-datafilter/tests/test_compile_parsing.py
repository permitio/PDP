import json

from permit_datafilter.compile_api.schemas import CRTerm, CompileResponse


COMPILE_RESPONE_RBAC_NO_SUPPORT_BLOCK = """{
  "result": {
    "queries": [
      [
        {
          "index": 0,
          "terms": [
            {
              "type": "ref",
              "value": [
                {
                  "type": "var",
                  "value": "eq"
                }
              ]
            },
            {
              "type": "ref",
              "value": [
                {
                  "type": "var",
                  "value": "input"
                },
                {
                  "type": "string",
                  "value": "resource"
                },
                {
                  "type": "string",
                  "value": "tenant"
                }
              ]
            },
            {
              "type": "string",
              "value": "default"
            }
          ]
        }
      ],
      [
        {
          "index": 0,
          "terms": [
            {
              "type": "ref",
              "value": [
                {
                  "type": "var",
                  "value": "eq"
                }
              ]
            },
            {
              "type": "ref",
              "value": [
                {
                  "type": "var",
                  "value": "input"
                },
                {
                  "type": "string",
                  "value": "resource"
                },
                {
                  "type": "string",
                  "value": "tenant"
                }
              ]
            },
            {
              "type": "string",
              "value": "second"
            }
          ]
        }
      ]
    ]
  }
}
"""


COMPILE_RESPONE_RBAC_WITH_SUPPORT_BLOCK = """{
  "result": {
    "queries": [
      [
        {
          "index": 0,
          "terms": [
            {
              "type": "ref",
              "value": [
                {
                  "type": "var",
                  "value": "gt"
                }
              ]
            },
            {
              "type": "call",
              "value": [
                {
                  "type": "ref",
                  "value": [
                    {
                      "type": "var",
                      "value": "count"
                    }
                  ]
                },
                {
                  "type": "ref",
                  "value": [
                    {
                      "type": "var",
                      "value": "data"
                    },
                    {
                      "type": "string",
                      "value": "partial"
                    },
                    {
                      "type": "string",
                      "value": "example"
                    },
                    {
                      "type": "string",
                      "value": "rbac4"
                    },
                    {
                      "type": "string",
                      "value": "allowed"
                    }
                  ]
                }
              ]
            },
            {
              "type": "number",
              "value": 0
            }
          ]
        }
      ]
    ],
    "support": [
      {
        "package": {
          "path": [
            {
              "type": "var",
              "value": "data"
            },
            {
              "type": "string",
              "value": "partial"
            },
            {
              "type": "string",
              "value": "example"
            },
            {
              "type": "string",
              "value": "rbac4"
            }
          ]
        },
        "rules": [
          {
            "body": [
              {
                "index": 0,
                "terms": [
                  {
                    "type": "ref",
                    "value": [
                      {
                        "type": "var",
                        "value": "eq"
                      }
                    ]
                  },
                  {
                    "type": "ref",
                    "value": [
                      {
                        "type": "var",
                        "value": "input"
                      },
                      {
                        "type": "string",
                        "value": "resource"
                      },
                      {
                        "type": "string",
                        "value": "tenant"
                      }
                    ]
                  },
                  {
                    "type": "string",
                    "value": "default"
                  }
                ]
              }
            ],
            "head": {
              "name": "allowed",
              "key": {
                "type": "string",
                "value": "user 'asaf' has role 'editor' in tenant 'default' which grants permission 'task:read'"
              },
              "ref": [
                {
                  "type": "var",
                  "value": "allowed"
                }
              ]
            }
          },
          {
            "body": [
              {
                "index": 0,
                "terms": [
                  {
                    "type": "ref",
                    "value": [
                      {
                        "type": "var",
                        "value": "eq"
                      }
                    ]
                  },
                  {
                    "type": "ref",
                    "value": [
                      {
                        "type": "var",
                        "value": "input"
                      },
                      {
                        "type": "string",
                        "value": "resource"
                      },
                      {
                        "type": "string",
                        "value": "tenant"
                      }
                    ]
                  },
                  {
                    "type": "string",
                    "value": "second"
                  }
                ]
              }
            ],
            "head": {
              "name": "allowed",
              "key": {
                "type": "string",
                "value": "user 'asaf' has role 'viewer' in tenant 'second' which grants permission 'task:read'"
              },
              "ref": [
                {
                  "type": "var",
                  "value": "allowed"
                }
              ]
            }
          }
        ]
      }
    ]
  }
}
"""


def test_parse_compile_response_rbac_no_support_block():
    response = json.loads(COMPILE_RESPONE_RBAC_NO_SUPPORT_BLOCK)
    res = CompileResponse(**response)
    assert res.result.queries is not None
    assert len(res.result.queries.__root__) == 2

    first_query = res.result.queries.__root__[0]
    len(first_query.__root__) == 1

    first_query_expression = first_query.__root__[0]
    assert first_query_expression.index == 0
    assert len(first_query_expression.terms) == 3

    assert first_query_expression.terms[0].type == "ref"
    assert first_query_expression.terms[1].type == "ref"
    assert first_query_expression.terms[2].type == "string"
    assert first_query_expression.terms[2].value == "default"

    second_query = res.result.queries.__root__[1]
    len(second_query.__root__) == 1

    second_query_expression = second_query.__root__[0]
    assert second_query_expression.index == 0
    assert len(second_query_expression.terms) == 3

    assert second_query_expression.terms[0].type == "ref"
    assert second_query_expression.terms[1].type == "ref"
    assert second_query_expression.terms[2].type == "string"
    assert second_query_expression.terms[2].value == "second"


def test_parse_compile_response_rbac_with_support_block():
    response = json.loads(COMPILE_RESPONE_RBAC_WITH_SUPPORT_BLOCK)
    res = CompileResponse(**response)
    assert res.result.queries is not None
    assert len(res.result.queries.__root__) == 1  # 1 query

    first_query = res.result.queries.__root__[0]
    len(first_query.__root__) == 1  # 1 expression

    first_query_expression = first_query.__root__[0]
    assert first_query_expression.index == 0
    assert len(first_query_expression.terms) == 3

    assert first_query_expression.terms[0].type == "ref"  # operator
    len(first_query_expression.terms[0].value) == 1
    op = CRTerm(**first_query_expression.terms[0].value[0])
    assert op.type == "var"
    assert op.value == "gt"

    assert first_query_expression.terms[1].type == "call"
    len(first_query_expression.terms[1].value) == 2

    assert first_query_expression.terms[2].type == "number"
    assert first_query_expression.terms[2].value == 0

    assert res.result.support is not None
    assert len(res.result.support.__root__) == 1  # 1 support module
