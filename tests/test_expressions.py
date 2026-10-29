from __future__ import annotations

from typing import Any

import pytest

from govflow.expressions import (
    AllOf,
    AnyOf,
    Compare,
    Not,
    PolicyError,
    Quantified,
    parse_expression,
    resolve_path,
    unavailable_reason,
)

DATA: dict[str, Any] = {
    "name": "repo",
    "count": 3,
    "flag": True,
    "tags": ["a", "b"],
    "nested": {"value": "x"},
    "rules": [
        {"port": 22, "cidr": "0.0.0.0/0"},
        {"port": 443, "cidr": "0.0.0.0/0"},
    ],
}


@pytest.mark.parametrize(
    ("op", "path", "value", "expected"),
    [
        ("eq", "name", "repo", True),
        ("eq", "name", "other", False),
        ("ne", "name", "other", True),
        ("in", "name", ["repo", "x"], True),
        ("not_in", "name", ["x"], True),
        ("contains", "tags", "a", True),
        ("contains", "tags", "z", False),
        ("not_contains", "tags", "z", True),
        ("contains", "name", "ep", True),
        ("contains", "name", 1, False),
        ("contains", "count", 3, False),
        ("gt", "count", 2, True),
        ("gte", "count", 3, True),
        ("lt", "count", 3, False),
        ("lte", "count", 3, True),
        ("gt", "name", 1, False),
        ("gt", "flag", 0, False),
        ("eq", "nested.value", "x", True),
        ("eq", "missing.path", None, True),
    ],
)
def test_comparisons(op: str, path: str, value: Any, expected: bool) -> None:
    assert Compare(path, op, value).evaluate(DATA, {}) is expected


@pytest.mark.parametrize(
    ("op", "path", "expected"),
    [
        ("exists", "name", True),
        ("exists", "nope", False),
        ("missing", "nope", True),
        ("truthy", "flag", True),
        ("falsy", "nope", True),
    ],
)
def test_valueless_operators(op: str, path: str, expected: bool) -> None:
    assert Compare(path, op).evaluate(DATA, {}) is expected


def test_unavailable_data_yields_unknown() -> None:
    unavailable = {"nested": "needs admin"}
    assert Compare("nested.value", "eq", "x").evaluate(DATA, unavailable) is None
    assert unavailable_reason("nested.value", unavailable) == "needs admin"
    assert unavailable_reason("nested", {"nested.value": "r"}) == "r"
    assert unavailable_reason("name", unavailable) is None


def test_three_valued_logic() -> None:
    true, false, unknown = (
        Compare("flag", "truthy"),
        Compare("flag", "falsy"),
        Compare("x", "exists"),
    )
    unavailable = {"x": "hidden"}
    assert AllOf((true, unknown)).evaluate(DATA, unavailable) is None
    assert AllOf((false, unknown)).evaluate(DATA, unavailable) is False
    assert AllOf((true, true)).evaluate(DATA, unavailable) is True
    assert AnyOf((true, unknown)).evaluate(DATA, unavailable) is True
    assert AnyOf((false, unknown)).evaluate(DATA, unavailable) is None
    assert AnyOf((false, false)).evaluate(DATA, unavailable) is False
    assert Not(unknown).evaluate(DATA, unavailable) is None
    assert Not(true).evaluate(DATA, unavailable) is False


def test_quantifiers() -> None:
    ssh = Compare("port", "eq", 22)
    assert Quantified("any_item", "rules", ssh).evaluate(DATA, {}) is True
    assert Quantified("all_items", "rules", ssh).evaluate(DATA, {}) is False
    assert Quantified("no_item", "rules", ssh).evaluate(DATA, {}) is False
    assert Quantified("no_item", "absent", ssh).evaluate(DATA, {}) is True
    assert Quantified("all_items", "absent", ssh).evaluate(DATA, {}) is True
    assert Quantified("any_item", "name", ssh).evaluate(DATA, {}) is False
    assert Quantified("any_item", "tags", Compare("value", "eq", "b")).evaluate(DATA, {}) is True
    assert Quantified("any_item", "rules", ssh).evaluate(DATA, {"rules": "hidden"}) is None


def test_parse_builds_tree_and_collects_paths() -> None:
    expression = parse_expression(
        {
            "all": [
                {"path": "name", "op": "eq", "value": "repo"},
                {"not": {"path": "flag", "op": "falsy"}},
                {
                    "any": [
                        {"path": "count", "op": "gte", "value": 1},
                        {"path": "name", "op": "exists"},
                    ]
                },
                {
                    "no_item": {
                        "path": "rules",
                        "where": {"path": "port", "op": "eq", "value": 3389},
                    }
                },
            ]
        }
    )
    assert expression.evaluate(DATA, {}) is True
    assert expression.paths() == ("name", "flag", "count", "rules")


@pytest.mark.parametrize(
    ("node", "message"),
    [
        ([], "non-empty mapping"),
        ({"all": []}, "non-empty list"),
        ({"all": [{"path": "a", "op": "exists"}], "any": []}, "unexpected keys"),
        ({"no_item": {"path": "a"}}, "exactly 'path' and 'where'"),
        ({"path": "a"}, "needs 'path' and 'op'"),
        ({"path": "a b", "op": "exists"}, "dotted attribute path"),
        ({"path": "a", "op": "regex", "value": "x"}, "unknown operator"),
        ({"path": "a", "op": "exists", "value": 1}, "takes no value"),
        ({"path": "a", "op": "eq"}, "needs a value"),
        ({"path": "a", "op": "in", "value": "x"}, "needs a list"),
        ({"path": "a", "op": "gt", "value": "1"}, "needs a number"),
        ({"path": "a", "op": "eq", "value": 1, "extra": 2}, "unexpected keys"),
    ],
)
def test_parse_rejects_malformed_conditions(node: Any, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        parse_expression(node)


def test_resolve_path_handles_non_mappings() -> None:
    assert resolve_path(DATA, "name.inner") is None
    assert resolve_path(DATA, "nested.value") == "x"
