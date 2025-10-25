"""HTTP message abstraction used by the mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional


@dataclass
class HttpRequest:
    """Lightweight representation of an HTTP request."""

    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes
    parameters: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_burp(cls, helpers, message_info) -> "HttpRequest":  # pragma: no cover - requires Burp
        request = message_info.getRequest()
        analyzed = helpers.analyzeRequest(message_info)
        headers = {}
        for header in analyzed.getHeaders():
            if ":" in header:
                name, value = header.split(":", 1)
                headers[name.strip()] = value.strip()
        body = request[analyzed.getBodyOffset():]
        method = analyzed.getMethod()
        url = analyzed.getUrl().toString()
        parameters = {
            parameter.getName(): parameter.getValue()
            for parameter in analyzed.getParameters()
        }
        return cls(method=method, url=url, headers=headers, body=body, parameters=parameters)

    @property
    def body_text(self) -> str:
        try:
            return self.body.decode("utf-8")
        except UnicodeDecodeError:
            return self.body.decode("latin-1", errors="ignore")

    def iter_parameters(self) -> Iterable[tuple[str, str]]:
        return list(self.parameters.items())


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes

    def json(self) -> Optional[dict]:
        try:
            import json

            return json.loads(self.body.decode("utf-8"))
        except Exception:  # pragma: no cover - defensive
            return None


__all__ = ["HttpRequest", "HttpResponse"]
