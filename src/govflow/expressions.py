"""A small declarative condition language for policies.

Checks are trees of comparisons evaluated with three-valued logic: True,
False, or None when the data needed was not available (for example because
the token lacked permission). Nothing in a policy is ever executed as code.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

Truth = bool | None

OPERATORS = frozenset(
    {
        "eq",
        "ne",
        "in",
        "not_in",
        "contains",
        "not_contains",
        "gt",
        "gte",
        "lt",
        "lte",
        "exists",
        "missing",
        "truthy",
        "falsy",
    }
)
QUANTIFIERS = ("any_item", "all_items", "no_item")
_VALUELESS = frozenset({"exists", "missing", "truthy", "falsy"})
_NUMERIC = frozenset({"gt", "gte", "lt", "lte"})
_LIST_VALUED = frozenset({"in", "not_in"})
_PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")


class PolicyError(ValueError):
    """A policy file or one of its conditions is malformed."""


def resolve_path(data: Mapping[str, Any], path: str) -> Any:
    """Return the value at a dotted path, or None when any segment is absent."""
    current: Any = data
    for segment in path.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            return None
        current = current[segment]
    return current


def unavailable_reason(path: str, unavailable: Mapping[str, str]) -> str | None:
    for prefix, reason in unavailable.items():
        if path == prefix or path.startswith(prefix + ".") or prefix.startswith(path + "."):
            return reason
    return None


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _compare(op: str, actual: Any, expected: Any) -> bool:
    if op == "exists":
        return actual is not None
    if op == "missing":
        return actual is None
    if op == "truthy":
        return bool(actual)
    if op == "falsy":
        return not actual
    if op == "eq":
        return bool(actual == expected)
    if op == "ne":
        return bool(actual != expected)
    if op == "in":
        return actual in expected
    if op == "not_in":
        return actual not in expected
    if op in ("contains", "not_contains"):
        if isinstance(actual, str):
            found = isinstance(expected, str) and expected in actual
        else:
            found = isinstance(actual, list | tuple) and expected in actual
        return found if op == "contains" else not found
    if not (_is_number(actual) and _is_number(expected)):
        return False
    if op == "gt":
        return bool(actual > expected)
    if op == "gte":
        return bool(actual >= expected)
    if op == "lt":
        return bool(actual < expected)
    return bool(actual <= expected)


def _all(results: Sequence[Truth]) -> Truth:
    if any(result is False for result in results):
        return False
    if any(result is None for result in results):
        return None
    return True


def _any(results: Sequence[Truth]) -> Truth:
    if any(result is True for result in results):
        return True
    if any(result is None for result in results):
        return None
    return False


def _unique(paths: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(paths))


class Expression:
    def evaluate(self, data: Mapping[str, Any], unavailable: Mapping[str, str]) -> Truth:
        raise NotImplementedError

    def paths(self) -> tuple[str, ...]:
        """Resource attribute paths this expression reads (used for evidence)."""
        raise NotImplementedError


@dataclass(frozen=True)
class Compare(Expression):
    path: str
    op: str
    value: Any = None

    def evaluate(self, data: Mapping[str, Any], unavailable: Mapping[str, str]) -> Truth:
        if unavailable_reason(self.path, unavailable) is not None:
            return None
        return _compare(self.op, resolve_path(data, self.path), self.value)

    def paths(self) -> tuple[str, ...]:
        return (self.path,)


@dataclass(frozen=True)
class AllOf(Expression):
    items: tuple[Expression, ...]

    def evaluate(self, data: Mapping[str, Any], unavailable: Mapping[str, str]) -> Truth:
        return _all([item.evaluate(data, unavailable) for item in self.items])

    def paths(self) -> tuple[str, ...]:
        return _unique([path for item in self.items for path in item.paths()])


@dataclass(frozen=True)
class AnyOf(Expression):
    items: tuple[Expression, ...]

    def evaluate(self, data: Mapping[str, Any], unavailable: Mapping[str, str]) -> Truth:
        return _any([item.evaluate(data, unavailable) for item in self.items])

    def paths(self) -> tuple[str, ...]:
        return _unique([path for item in self.items for path in item.paths()])


@dataclass(frozen=True)
class Not(Expression):
    inner: Expression

    def evaluate(self, data: Mapping[str, Any], unavailable: Mapping[str, str]) -> Truth:
        result = self.inner.evaluate(data, unavailable)
        return None if result is None else not result

    def paths(self) -> tuple[str, ...]:
        return self.inner.paths()


@dataclass(frozen=True)
class Quantified(Expression):
    kind: str
    path: str
    where: Expression

    def evaluate(self, data: Mapping[str, Any], unavailable: Mapping[str, str]) -> Truth:
        if unavailable_reason(self.path, unavailable) is not None:
            return None
        items = resolve_path(data, self.path)
        if items is None:
            items = []
        if not isinstance(items, list):
            return False
        results = [
            self.where.evaluate(item if isinstance(item, Mapping) else {"value": item}, {})
            for item in items
        ]
        if self.kind == "any_item":
            return _any(results)
        if self.kind == "all_items":
            return _all(results)
        matched = _any(results)
        return None if matched is None else not matched

    def paths(self) -> tuple[str, ...]:
        return (self.path,)


def _path(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _PATH.fullmatch(value):
        raise PolicyError(f"{where}: expected a dotted attribute path, got {value!r}")
    return value


def _only(keys: set[str], allowed: set[str], where: str) -> None:
    extra = keys - allowed
    if extra:
        raise PolicyError(f"{where}: unexpected keys {sorted(extra)}")


def _children(node: Mapping[str, Any], key: str, where: str) -> tuple[Expression, ...]:
    children = node[key]
    if not isinstance(children, list) or not children:
        raise PolicyError(f"{where}.{key}: expected a non-empty list")
    return tuple(
        parse_expression(child, f"{where}.{key}[{index}]") for index, child in enumerate(children)
    )


def parse_expression(node: Any, where: str = "check") -> Expression:
    """Turn a YAML mapping into an expression tree, rejecting anything unexpected."""
    if not isinstance(node, Mapping) or not node:
        raise PolicyError(f"{where}: expected a non-empty mapping")
    keys = set(node)
    if "all" in keys:
        _only(keys, {"all"}, where)
        return AllOf(_children(node, "all", where))
    if "any" in keys:
        _only(keys, {"any"}, where)
        return AnyOf(_children(node, "any", where))
    if "not" in keys:
        _only(keys, {"not"}, where)
        return Not(parse_expression(node["not"], f"{where}.not"))
    for kind in QUANTIFIERS:
        if kind in keys:
            _only(keys, {kind}, where)
            body = node[kind]
            if not isinstance(body, Mapping) or set(body) != {"path", "where"}:
                raise PolicyError(f"{where}.{kind}: expected exactly 'path' and 'where'")
            return Quantified(
                kind,
                _path(body["path"], f"{where}.{kind}.path"),
                parse_expression(body["where"], f"{where}.{kind}.where"),
            )
    return _parse_compare(node, keys, where)


def _parse_compare(node: Mapping[str, Any], keys: set[str], where: str) -> Compare:
    _only(keys, {"path", "op", "value"}, where)
    if "path" not in keys or "op" not in keys:
        raise PolicyError(f"{where}: a comparison needs 'path' and 'op'")
    path = _path(node["path"], f"{where}.path")
    op = node["op"]
    if op not in OPERATORS:
        raise PolicyError(f"{where}.op: unknown operator {op!r}")
    if op in _VALUELESS:
        if "value" in keys:
            raise PolicyError(f"{where}: operator {op!r} takes no value")
        return Compare(path, op)
    if "value" not in keys:
        raise PolicyError(f"{where}: operator {op!r} needs a value")
    value = node["value"]
    if op in _LIST_VALUED and not isinstance(value, list):
        raise PolicyError(f"{where}.value: operator {op!r} needs a list")
    if op in _NUMERIC and not _is_number(value):
        raise PolicyError(f"{where}.value: operator {op!r} needs a number")
    return Compare(path, op, value)
