"""Swing UI façade used by the Burp extension."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Optional


@dataclass
class _PythonPanel:
    """Fallback panel used when Swing is unavailable.

    The object mimics the minimal API Burp Suite expects.  It allows the
    module to be imported during testing without pulling in Swing.
    """

    title: str

    def getComponent(self):  # pragma: no cover - trivial wrapper
        return self


class MainPanel:
    """UI container for the extension.

    The class exposes the behaviour required by Burp's :class:`ITab`
    interface.  When running inside Burp Suite the Swing components are
    constructed, otherwise a light-weight Python object is returned so the
    unit tests can import this module without errors.
    """

    def __init__(self, mutator, executor) -> None:
        self._mutator = mutator
        self._executor = executor
        self._tab_caption = "IDORMe"
        self._component = self._build_component()

    def _build_component(self):
        swing_spec = importlib.util.find_spec("javax.swing")
        if not swing_spec:
            return _PythonPanel(self._tab_caption)

        from javax.swing import JPanel, JScrollPane, JTextArea  # type: ignore
        from java.awt import BorderLayout  # type: ignore

        panel = JPanel(BorderLayout())
        self._text_area = JTextArea()
        self._text_area.setEditable(False)
        scroll = JScrollPane(self._text_area)
        panel.add(scroll, BorderLayout.CENTER)
        self._log("IDORMe extension initialised")
        return panel

    # ------------------------------------------------------------------
    # ITab compatibility
    # ------------------------------------------------------------------
    def getTabCaption(self):  # pragma: no cover - trivial
        return self._tab_caption

    def getUiComponent(self):  # pragma: no cover - trivial
        return getattr(self._component, "getComponent", lambda: self._component)()

    # ------------------------------------------------------------------
    # UI helpers
    # ------------------------------------------------------------------
    def _log(self, message: str) -> None:
        text_area = getattr(self, "_text_area", None)
        if text_area is None:
            return
        text_area.append(message + "\n")

    def record_execution(self, payload: str, owner: Optional[str]) -> None:
        self._log(f"Payload {payload} queued for owner {owner or 'unknown'}")


__all__ = ["MainPanel"]
