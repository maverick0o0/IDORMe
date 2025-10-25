import random
from importlib import util as importlib_util
from pathlib import Path

module_path = Path(__file__).resolve().parent.parent / "src" / "idorme" / "request_utils.py"
spec = importlib_util.spec_from_file_location("idorme.request_utils", module_path)
request_utils = importlib_util.module_from_spec(spec)
assert spec.loader is not None  # satisfy type checkers
spec.loader.exec_module(request_utils)

pick_random_identifier = request_utils.pick_random_identifier


def test_pick_random_identifier_excludes_string_values(monkeypatch):
    calls = iter([1234, 5678])

    def fake_randint(start, stop):
        return next(calls)

    monkeypatch.setattr(random, "randint", fake_randint)

    assert pick_random_identifier(exclude=["1234"]) == "5678"
