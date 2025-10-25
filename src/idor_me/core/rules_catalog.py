"""Mutation rule catalog.

Each rule is represented by :class:`MutationRule`.  The default catalog
exposes a deterministic ordering which is important for reproducible
test runs and ensures Burp users see consistent behaviour when rerunning
mutations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List

MutationGenerator = Callable[["MutationContext"], Iterable[str]]


@dataclass(frozen=True)
class MutationRule:
    """Describes a mutation rule."""

    name: str
    description: str
    order: int
    generator: MutationGenerator

    def generate(self, context: "MutationContext") -> List[str]:
        """Return the list of payloads produced by this rule."""

        seen = set()
        results: List[str] = []
        for payload in self.generator(context):
            if payload in seen:
                continue
            seen.add(payload)
            results.append(payload)
        return results


class MutationContext:
    """A minimal context exposed to rules.

    Only the attributes required by the tests are implemented.  The class
    lives in this module to avoid a circular import between the rules and
    the mutation engine.
    """

    def __init__(self, request: HttpRequest, parameter: str, value: str) -> None:
        self.request = request
        self.parameter = parameter
        self.value = value

    @property
    def is_numeric(self) -> bool:
        return self.value.isdigit()

    @property
    def is_boolean(self) -> bool:
        return self.value.lower() in {"true", "false", "0", "1"}


def build_default_rules() -> List[MutationRule]:
    """Return the default ordered rule set."""

    def increment(context: MutationContext) -> Iterable[str]:
        if context.is_numeric:
            yield str(int(context.value) + 1)

    def decrement(context: MutationContext) -> Iterable[str]:
        if context.is_numeric and int(context.value) > 0:
            yield str(max(int(context.value) - 1, 0))

    def boolean_flip(context: MutationContext) -> Iterable[str]:
        if context.is_boolean:
            if context.value.lower() in {"true", "1"}:
                yield "false"
                yield "0"
            else:
                yield "true"
                yield "1"

    def owner_placeholder(context: MutationContext) -> Iterable[str]:
        if "user" in context.parameter.lower():
            yield "{{CURRENT_USER}}"
            yield "{{OTHER_USER}}"

    rules = [
        MutationRule("numeric_increment", "Increment numeric values", 10, increment),
        MutationRule("numeric_decrement", "Decrement numeric values", 20, decrement),
        MutationRule("boolean_flip", "Flip boolean values", 30, boolean_flip),
        MutationRule(
            "owner_placeholder",
            "Injects owner resolution templates",
            40,
            owner_placeholder,
        ),
    ]
    rules.sort(key=lambda rule: rule.order)
    return rules


__all__ = ["MutationRule", "MutationContext", "build_default_rules"]
