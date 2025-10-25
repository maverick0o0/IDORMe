import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from idor_me.core.httpmsg import HttpRequest
from idor_me.core.mutator import MutationContext, Mutator
from idor_me.core.rules_catalog import build_default_rules


class RulesCatalogTests(unittest.TestCase):
    def setUp(self):
        self.mutator = Mutator(build_default_rules())

    def test_rules_sorted_by_priority(self):
        request = HttpRequest(None, "GET", "/api/users/101", "", [], "")
        context = MutationContext.build(request, {"name": None, "attacker": None, "victim": None})
        mutations = self.mutator.generate_mutations(context)
        rule_order = [mutation.rule_id for mutation in mutations[:5]]
        self.assertIn("G-01", rule_order[0])

    def test_query_rules_included(self):
        request = HttpRequest(None, "GET", "/api/users/edit", "userId=100", [], "")
        context = MutationContext.build(request, {"name": "userId", "attacker": "100", "victim": "200"})
        mutations = self.mutator.generate_mutations(context)
        ids = set([mutation.rule_id for mutation in mutations])
        self.assertIn("B3-03", ids)
        self.assertIn("G-02", ids)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
