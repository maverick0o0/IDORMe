import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from idor_me.core.httpmsg import HttpRequest
from idor_me.core.mutator import MutationContext, Mutator
from idor_me.core.rules_catalog import build_default_rules


def build_request(method, path, query="", headers=None, body="", content_type=None):
    headers = headers or []
    if content_type:
        headers.append(("Content-Type", content_type))
    request = HttpRequest(service=None, method=method, path=path, query=query, headers=headers, body=body)
    return request


class MutatorTests(unittest.TestCase):
    def setUp(self):
        self.mutator = Mutator(build_default_rules())

    def test_path_base_rules_do_not_add_body_on_method_flip(self):
        request = build_request("GET", "/api/users/101")
        context = MutationContext.build(request, {"name": None, "attacker": None, "victim": None})
        mutations = self.mutator.generate_mutations(context)
        rule_ids = [mutation.rule_id for mutation in mutations if mutation.rule_id.startswith("B1-01")]
        self.assertTrue(rule_ids)
        for mutation in mutations:
            if mutation.rule_id == "B1-01":
                self.assertIsNone(mutation.body_bytes)

    def test_query_base_generates_body_only_for_move_rules(self):
        request = build_request("GET", "/api/users/edit", "userId=100")
        context = MutationContext.build(request, {"name": "userId", "attacker": "100", "victim": "200"})
        mutations = self.mutator.generate_mutations(context)
        body_rules = [m for m in mutations if m.body_bytes]
        ids = set([m.rule_id for m in body_rules])
        self.assertIn("B3-05", ids)
        for mutation in mutations:
            if mutation.rule_id == "B3-04":
                self.assertIsNone(mutation.body_bytes)

    def test_body_base_duplicate_keys(self):
        body = '{"id": 1}'
        headers = [("Content-Type", "application/json")]
        request = HttpRequest(None, "POST", "/api/users/edit", "", headers, body)
        context = MutationContext.build(request, {"name": "id", "attacker": "1", "victim": "2"})
        mutations = self.mutator.generate_mutations(context)
        payloads = [m.body_bytes for m in mutations if m.rule_id == "B2-06"]
        self.assertEqual(len(payloads), 2)
        for payload in payloads:
            self.assertIn('"id"', payload)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
