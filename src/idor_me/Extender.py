"""IDORMe Burp extension.

Design overview:
1. :class:`BurpExtender` wires Burp APIs (callbacks, helpers, menu/tab).
2. UI state lives in :class:`MainPanel`, which exposes user inputs/options.
3. :mod:`mutator` builds mutation batches from the declarative catalog.
4. :mod:`executor` sends mutations, aggregates results, and feeds the UI.
5. Double-clicking a result opens Burp message editors backed by the extender.
"""

try:  # pragma: no cover - Burp runtime
    from burp import (  # type: ignore
        IBurpExtender,
        ITab,
        IContextMenuFactory,
        IHttpListener,
        IMessageEditorController,
    )
except Exception:  # pragma: no cover - unit tests
    class IBurpExtender(object):
        pass

    class ITab(object):
        pass

    class IContextMenuFactory(object):
        pass

    class IHttpListener(object):
        pass

    class IMessageEditorController(object):
        pass

from .core.executor import RequestExecutor
from .core.mutator import Mutator, MutationContext
from .core.owner_infer import OwnerInference
from .core.httpmsg import HttpRequest
from .ui.MainPanel import MainPanel


class BurpExtender(
    IBurpExtender,
    ITab,
    IContextMenuFactory,
    IHttpListener,
    IMessageEditorController,
):
    EXTENSION_NAME = "IDORMe"

    def __init__(self):
        self._callbacks = None
        self._helpers = None
        self._mutator = Mutator()
        self._owner_inference = OwnerInference()
        self._executor = RequestExecutor(self._owner_inference)
        self._main_panel = MainPanel(self._mutator, self._executor)
        self._main_panel.set_run_handler(self._run_last_request)
        self._main_panel.set_stop_handler(self._executor.stop)
        self._main_panel.set_clear_handler(self._main_panel.clear_results)
        self._main_panel.set_export_handler(self._main_panel.export_csv)
        self._main_panel.set_row_handler(self._show_result_viewers)
        self._executor.configure(owner_inference=self._owner_inference, result_listener=self._handle_result)
        self._current_result = None
        self._last_request = None
        self._last_message = None
        self._request_editor = None
        self._response_editor = None
        self._viewer_dialog = None

    # ------------------------------------------------------------------
    # Burp lifecycle
    # ------------------------------------------------------------------
    def registerExtenderCallbacks(self, callbacks):  # pragma: no cover - Burp entry point
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        self._executor.configure(callbacks=callbacks, helpers=self._helpers)
        self._request_editor = callbacks.createMessageEditor(self, False)
        self._response_editor = callbacks.createMessageEditor(self, True)

    # ------------------------------------------------------------------
    # ITab implementation
    # ------------------------------------------------------------------
    def getTabCaption(self):  # pragma: no cover - Burp calls
        return self.EXTENSION_NAME

    def getUiComponent(self):  # pragma: no cover - Burp calls
        return self._main_panel.getComponent()

    # ------------------------------------------------------------------
    # Context menu factory
    # ------------------------------------------------------------------
    def createMenuItems(self, invocation):  # pragma: no cover - Burp callback
        selected = invocation.getSelectedMessages()
        if not selected:
            return []
        try:
            from java.util import ArrayList
            from javax.swing import JMenuItem
        except Exception:
            return []
        items = ArrayList()
        menu_item = JMenuItem("Send to IDORMe")

        def _perform(_event, messages=selected):
            self._handle_context_messages(messages)

        menu_item.addActionListener(_perform)
        items.add(menu_item)
        return items

    # ------------------------------------------------------------------
    # IHttpListener
    # ------------------------------------------------------------------
    def processHttpMessage(self, tool_flag, message_is_request, message_info):  # pragma: no cover - Burp callback
        pass

    # ------------------------------------------------------------------
    # IMessageEditorController
    # ------------------------------------------------------------------
    def getHttpService(self):  # pragma: no cover - Burp callback
        if not self._current_result:
            return None
        return self._last_message.getHttpService() if self._last_message else None

    def getRequest(self):  # pragma: no cover - Burp callback
        if not self._current_result:
            return None
        return self._current_result.get("raw_request")

    def getResponse(self):  # pragma: no cover - Burp callback
        if not self._current_result or not self._current_result.get("raw_response"):
            return None
        return self._current_result["raw_response"].getResponse()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _handle_context_messages(self, messages):
        if not messages:
            return
        self._main_panel.clear_results()
        message = messages[0]
        self._last_message = message
        request = HttpRequest.from_burp(self._helpers, message)
        self._last_request = request
        self._run_for_request(request, message)

    def _run_for_request(self, request, message_info):
        user_inputs = self._main_panel.get_user_inputs()
        context = MutationContext.build(request, user_inputs)
        options = self._main_panel.get_execution_options()
        self._executor.set_options(options)
        mutations = self._mutator.generate_mutations(
            context,
            apply_global=options.apply_global,
            apply_specific=options.apply_specific,
        )
        if not mutations:
            return
        baseline_response = message_info
        self._executor.enqueue(request, baseline_response, mutations)

    def _handle_result(self, result):
        self._main_panel.display_result(result)

    def _run_last_request(self):
        if self._last_request and self._last_message:
            self._main_panel.clear_results()
            self._run_for_request(self._last_request, self._last_message)

    def _show_result_viewers(self, result):
        self._current_result = result
        if not self._request_editor or not self._response_editor or not self._callbacks:
            return
        self._request_editor.setMessage(result.get("raw_request"), True)
        raw_response = result.get("raw_response")
        if raw_response:
            self._response_editor.setMessage(raw_response.getResponse(), False)
        self._ensure_viewer_dialog()
        if self._viewer_dialog:
            self._viewer_dialog.setVisible(True)

    def _ensure_viewer_dialog(self):
        if self._viewer_dialog or not self._callbacks or not self._request_editor:
            return
        try:
            from javax.swing import JDialog, JTabbedPane
        except Exception:
            return
        frame = self._callbacks.getBurpFrame()
        dialog = JDialog(frame, "IDORMe result", False)
        tabs = JTabbedPane()
        tabs.addTab("Request", self._request_editor.getComponent())
        tabs.addTab("Response", self._response_editor.getComponent())
        dialog.getContentPane().add(tabs)
        dialog.setSize(800, 600)
        self._viewer_dialog = dialog


__all__ = ["BurpExtender"]
