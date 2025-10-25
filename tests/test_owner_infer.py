import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from idor_me.core.owner_infer import OwnerInference


class OwnerInferenceTests(unittest.TestCase):
    def setUp(self):
        self.infer = OwnerInference()

    def test_extract_tokens_from_json(self):
        body = '{"userId": 101, "profile": {"email": "alice@example.com"}}'
        tokens = self.infer.extract_tokens(body)
        self.assertIn("101", tokens)
        self.assertIn("alice@example.com", tokens)

    def test_extract_tokens_from_xml(self):
        body = "<root><uid>200</uid><contact>bob@example.org</contact></root>"
        tokens = self.infer.extract_tokens(body)
        self.assertIn("200", tokens)
        self.assertIn("bob@example.org", tokens)

    def test_scoring_definite_when_status_changes(self):
        baseline_tokens = ["100"]
        result = self.infer.score(403, baseline_tokens, 200, '{"userId": 200}', 30, True)
        self.assertEqual(result["label"], "Definite")
        self.assertEqual(result["score"], 100)

    def test_scoring_likely_with_new_tokens(self):
        baseline_tokens = ["100"]
        result = self.infer.score(200, baseline_tokens, 200, '{"userId": 200}', 50, True)
        self.assertEqual(result["label"], "Likely")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
