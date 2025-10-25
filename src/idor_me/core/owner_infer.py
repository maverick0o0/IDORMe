"""Utilities for inferring request ownership."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

from .httpmsg import HttpRequest


@dataclass
class OwnerHint:
    source: str
    value: str


class OwnerInference:
    """Heuristically determine which account a request belongs to."""

    USER_PATTERNS = [
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"/users/(?P<user>[\w-]+)",
            r"/accounts/(?P<user>[\w-]+)",
            r"user_id=(?P<user>[\w-]+)",
        )
    ]

    def infer_owner(self, request: HttpRequest) -> Optional[str]:
        for hint in self._iterate_hints(request):
            if hint.value:
                return hint.value
        return None

    def _iterate_hints(self, request: HttpRequest) -> Iterable[OwnerHint]:
        path = request.url
        for pattern in self.USER_PATTERNS:
            match = pattern.search(path)
            if match:
                yield OwnerHint("url", match.group("user"))
        for name, value in request.iter_parameters():
            if name.lower() in {"user", "user_id", "account"}:
                yield OwnerHint("parameter", value)
        header_owner = request.headers.get("X-Acting-User")
        if header_owner:
            yield OwnerHint("header", header_owner)


__all__ = ["OwnerInference", "OwnerHint"]
