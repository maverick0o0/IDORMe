import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from idor_me.core.executor import RequestExecutor
from idor_me.core.httpmsg import HttpRequest, HttpResponse


class DummyHelpers(object):
    def analyzeResponse(self, response):  # pragma: no cover - should not be called
        raise AssertionError("analyzeResponse should not be invoked when response is None")


class DummyMessageInfo(object):
    def getResponse(self):
        return None


class HttpMessageTests(unittest.TestCase):
    def test_from_burp_handles_missing_response(self):
        response = HttpResponse.from_burp(DummyHelpers(), DummyMessageInfo())
        self.assertEqual(0, response.status_code)
        self.assertEqual([], response.headers)
        self.assertEqual("", response.body)

    def test_build_baseline_info_with_missing_response(self):
        executor = RequestExecutor()
        executor.helpers = DummyHelpers()
        request = HttpRequest(service=None, method="GET", path="/", query="", headers=[], body="")

        baseline = executor._build_baseline_info(request, DummyMessageInfo())

        self.assertIsNone(baseline["status"])
        self.assertEqual(0, baseline["length"])
        self.assertEqual(hashlib.sha256(b"").hexdigest(), baseline["hash"])
        self.assertEqual([], baseline["owner_tokens"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
