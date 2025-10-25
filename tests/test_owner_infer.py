from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from idor_me.core.httpmsg import HttpRequest
from idor_me.core.owner_infer import OwnerInference


def build_request(url="https://example.test/resources/1", parameters=None, headers=None):
    return HttpRequest(
        method="GET",
        url=url,
        headers=headers or {"Host": "example.test"},
        body=b"",
        parameters=parameters or {},
    )


class OwnerInferenceTests(unittest.TestCase):
    def test_owner_inferred_from_url(self):
        request = build_request(url="https://example.test/accounts/bob")
        inference = OwnerInference()
        self.assertEqual(inference.infer_owner(request), "bob")

    def test_owner_inferred_from_parameter(self):
        request = build_request(parameters={"user_id": "charlie"})
        inference = OwnerInference()
        self.assertEqual(inference.infer_owner(request), "charlie")

    def test_owner_inferred_from_header(self):
        request = build_request(headers={"X-Acting-User": "dan"})
        inference = OwnerInference()
        self.assertEqual(inference.infer_owner(request), "dan")

    def test_owner_unknown_when_no_hints(self):
        request = build_request(url="https://example.test/resources/42")
        inference = OwnerInference()
        self.assertIsNone(inference.infer_owner(request))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
