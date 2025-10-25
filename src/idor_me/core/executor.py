"""Executor responsible for replaying mutated HTTP requests."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

from .httpmsg import HttpRequest, HttpResponse

logger = logging.getLogger(__name__)

Transport = Callable[[HttpRequest, str], HttpResponse]


@dataclass
class ExecutionResult:
    request: HttpRequest
    payload: str
    response: Optional[HttpResponse]
    owner: Optional[str]


class RequestExecutor:
    """Simple synchronous executor used by the tests and UI."""

    def __init__(self, transport: Optional[Transport] = None) -> None:
        self._queue: List[tuple[HttpRequest, str, Optional[str]]] = []
        self._transport = transport
        self._history: List[ExecutionResult] = []

    @property
    def history(self) -> List[ExecutionResult]:
        return list(self._history)

    def enqueue(self, request: HttpRequest, payloads: Iterable[str], owner: Optional[str]) -> None:
        for payload in payloads:
            self._queue.append((request, payload, owner))
        self._drain()

    def _drain(self) -> None:
        while self._queue:
            request, payload, owner = self._queue.pop(0)
            response = self._perform(request, payload)
            self._history.append(ExecutionResult(request, payload, response, owner))

    def _perform(self, request: HttpRequest, payload: str) -> Optional[HttpResponse]:
        if not self._transport:
            logger.debug("No transport configured; mutation %s queued without execution", payload)
            return None
        try:
            return self._transport(request, payload)
        except Exception as exc:  # pragma: no cover - defensive logging only
            logger.exception("Transport raised during execution: %s", exc)
            return None


__all__ = ["RequestExecutor", "ExecutionResult"]
