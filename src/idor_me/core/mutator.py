"""Mutation engine assembling payloads from a catalog of rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator, List, Sequence

from .httpmsg import HttpRequest
from .rules_catalog import MutationContext as RuleContext
from .rules_catalog import MutationRule


@dataclass(frozen=True)
class MutationContext:
    """Describes the mutation target."""

    request: HttpRequest
    parameter: str
    value: str

    @classmethod
    def from_request(cls, request: HttpRequest) -> Iterator["MutationContext"]:
        for parameter, value in request.iter_parameters():
            yield cls(request=request, parameter=parameter, value=value)

    def to_rule_context(self) -> RuleContext:
        return RuleContext(self.request, self.parameter, self.value)


class Mutator:
    """Assembles mutations from a fixed rule catalog."""

    def __init__(self, rules: Sequence[MutationRule]):
        self._rules = sorted(rules, key=lambda rule: rule.order)

    @property
    def rules(self) -> Sequence[MutationRule]:
        return self._rules

    def generate_mutations(self, context: MutationContext) -> List[str]:
        payloads: List[str] = []
        for rule in self._rules:
            rule_payloads = rule.generate(context.to_rule_context())
            for payload in rule_payloads:
                if payload not in payloads:
                    payloads.append(payload)
        return payloads

    # These helper methods are primarily used by the UI but are exercised in
    # the unit tests to ensure we can inspect live traffic without raising
    # exceptions when operating outside of Burp Suite.
    def inspect_live_traffic(self, request: HttpRequest) -> None:
        for context in self.inspectable_contexts(request):
            self.generate_mutations(context)

    def inspectable_contexts(self, request: HttpRequest) -> List[MutationContext]:
        return list(MutationContext.from_request(request))


__all__ = ["Mutator", "MutationContext"]
