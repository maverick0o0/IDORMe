from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from idor_me.core.rules_catalog import MutationContext, build_default_rules


class RulesCatalogTests(unittest.TestCase):
    def test_rules_sorted_by_order(self):
        rules = build_default_rules()
        orders = [rule.order for rule in rules]
        self.assertEqual(orders, sorted(orders))

    def test_numeric_rules_generate_expected_payloads(self):
        request = object()
        context = MutationContext(request, "limit", "10")
        increment = next(rule for rule in build_default_rules() if rule.name == "numeric_increment")
        decrement = next(rule for rule in build_default_rules() if rule.name == "numeric_decrement")
        self.assertEqual(increment.generate(context), ["11"])
        self.assertEqual(decrement.generate(context), ["9"])

    def test_owner_placeholder_rule_only_applies_to_user_parameters(self):
        context_user = MutationContext(object(), "user", "bob")
        context_other = MutationContext(object(), "resource", "bob")
        owner_rule = next(rule for rule in build_default_rules() if rule.name == "owner_placeholder")
        self.assertEqual(owner_rule.generate(context_user), ["{{CURRENT_USER}}", "{{OTHER_USER}}"])
        self.assertEqual(owner_rule.generate(context_other), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
