import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parent.parent / "src" / "idorme" / "request_utils.py"
spec = importlib.util.spec_from_file_location("idorme.request_utils", MODULE_PATH)
request_utils = importlib.util.module_from_spec(spec)
assert spec is not None and spec.loader is not None
spec.loader.exec_module(request_utils)
RequestTemplate = request_utils.RequestTemplate


def test_set_query_pairs_encodes_plain_strings_without_bytes_prefix():
    template = RequestTemplate("GET", "/", "", [], b"")
    builder = template.builder()

    builder.set_query_pairs([("userId", 100)])

    assert builder.query_string == "userId=100"

