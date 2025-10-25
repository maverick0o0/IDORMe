from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from idor_me.core.httpmsg import HttpRequest
from idor_me.core.mutator import MutationContext, Mutator
from idor_me.core.rules_catalog import build_default_rules


def build_request(parameters):
    return HttpRequest(
        method="GET",
        url="https://example.test/users/123",
        headers={"Host": "example.test"},
        body=b"",
        parameters=parameters,
    )


class MutatorTests(unittest.TestCase):
    def test_mutation_generation_respects_rule_order(self):
        request = build_request({"user_id": "123", "active": "true"})
        mutator = Mutator(build_default_rules())
        contexts = list(MutationContext.from_request(request))
        self.assertEqual(contexts[0].parameter, "user_id")
        payloads = mutator.generate_mutations(contexts[0])
        self.assertEqual(payloads, ["124", "122", "{{CURRENT_USER}}", "{{OTHER_USER}}"])

    def test_boolean_mutations_added_for_boolean_parameters(self):
        request = build_request({"user_id": "5", "active": "true"})
        mutator = Mutator(build_default_rules())
        boolean_context = MutationContext(request, "active", "true")
        payloads = mutator.generate_mutations(boolean_context)
        self.assertEqual(payloads, ["false", "0"])

    def test_inspect_live_traffic_handles_missing_rules_gracefully(self):
        request = build_request({"unused": "value"})
        mutator = Mutator(build_default_rules())
        mutator.inspect_live_traffic(request)  # should not raise


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
