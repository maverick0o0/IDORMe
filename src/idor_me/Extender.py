"""Burp Suite extension entry point.

The implementation is written so that it can be imported inside a unit
-test friendly CPython environment.  When executed in Burp Suite the
extension will detect the presence of the Burp APIs and instantiate the
Swing based user interface and context menu actions required by the
project specification.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

from .core.executor import RequestExecutor
from .core.mutator import MutationContext, Mutator
from .core.rules_catalog import build_default_rules
from .core.httpmsg import HttpRequest
from .core.owner_infer import OwnerInference
from .ui.MainPanel import MainPanel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Burp API compatibility layer
# ---------------------------------------------------------------------------

_burp_spec = importlib.util.find_spec("burp")
if _burp_spec:
    burp = importlib.import_module("burp")
    IBurpExtender = getattr(burp, "IBurpExtender")
    IContextMenuFactory = getattr(burp, "IContextMenuFactory")
    IExtensionHelpers = getattr(burp, "IExtensionHelpers")
    IHttpListener = getattr(burp, "IHttpListener", object)
    IHttpRequestResponse = getattr(burp, "IHttpRequestResponse", object)
else:  # pragma: no cover - exercised only inside Burp
    class IBurpExtender:  # type: ignore[misc]
        """Fallback stub for static analysis and unit testing."""

    class IContextMenuFactory:  # type: ignore[misc]
        pass

    class IExtensionHelpers:  # type: ignore[misc]
        pass

    class IHttpListener:  # type: ignore[misc]
        pass

    class IHttpRequestResponse:  # type: ignore[misc]
        pass


@dataclass
class ContextMenuAction:
    """Represents a context menu action provided by the extension."""

    caption: str
    handler: Callable[[Iterable[HttpRequest]], None]


class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener):
    """Burp Suite extension wiring.

    The extender registers a single tab, context menu actions and routes
    HTTP messages through the mutation engine.
    """

    EXTENSION_NAME = "IDORMe"

    def __init__(self) -> None:
        self._callbacks = None
        self._helpers: Optional[IExtensionHelpers] = None
        self._mutator = Mutator(build_default_rules())
        self._executor = RequestExecutor()
        self._owner_inference = OwnerInference()
        self._main_panel = MainPanel(mutator=self._mutator, executor=self._executor)
        self._context_actions: List[ContextMenuAction] = [
            ContextMenuAction(
                "Send to IDORMe",
                handler=self._handle_context_menu_selection,
            )
        ]

    # ------------------------------------------------------------------
    # Burp callbacks lifecycle
    # ------------------------------------------------------------------
    def registerExtenderCallbacks(self, callbacks) -> None:  # pragma: no cover - invoked by Burp
        """Entry point used by Burp Suite."""

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.addSuiteTab(self._main_panel)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        logger.info("%s extension registered", self.EXTENSION_NAME)

    # ------------------------------------------------------------------
    # Context menu factory implementation
    # ------------------------------------------------------------------
    def createMenuItems(self, invocation):  # pragma: no cover - requires Burp
        selected_messages = invocation.getSelectedMessages()
        if not selected_messages:
            return []

        from java.util import ArrayList  # type: ignore
        from javax.swing import JMenuItem  # type: ignore

        menu_items = ArrayList()
        for action in self._context_actions:
            item = JMenuItem(action.caption)
            def _perform_action(_evt, handler=action.handler, messages=selected_messages):
                http_requests = [
                    HttpRequest.from_burp(self._helpers, message)  # type: ignore[arg-type]
                    for message in messages
                ]
                handler(http_requests)

            item.addActionListener(_perform_action)
            menu_items.add(item)
        return menu_items

    # ------------------------------------------------------------------
    # IHttpListener implementation
    # ------------------------------------------------------------------
    def processHttpMessage(self, tool_flag, message_is_request, message_info):  # pragma: no cover - requires Burp
        if not message_is_request or tool_flag != self._callbacks.TOOL_PROXY:
            return
        request = HttpRequest.from_burp(self._helpers, message_info)
        self._mutator.inspect_live_traffic(request)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _handle_context_menu_selection(self, http_requests: Iterable[HttpRequest]) -> None:
        for request in http_requests:
            for context in MutationContext.from_request(request):
                mutations = self._mutator.generate_mutations(context)
                owner = self._owner_inference.infer_owner(request)
                self._executor.enqueue(request, mutations, owner)


__all__ = ["BurpExtender", "ContextMenuAction"]
