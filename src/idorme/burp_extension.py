"""Burp Suite extension entry point for IDORMe."""
from __future__ import absolute_import

import threading

from burp import IBurpExtender, ITab, IContextMenuFactory

from java.util import ArrayList
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Dimension
from javax.swing import (
    JPanel,
    JButton,
    JTable,
    JScrollPane,
    JTextField,
    JLabel,
    JMenuItem,
    JOptionPane,
    JSplitPane,
    SwingUtilities,
)
from javax.swing.table import AbstractTableModel

from idorme.mutation_engine import MutationEngine, UserInput
from idorme.request_utils import parse_request_template


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    """IDORMe Burp Suite extension entry point."""

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("IDORMe")

        self._panel = IDORMePanel(callbacks, self._helpers)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)

    # ------------------------------------------------------------------
    def getTabCaption(self):
        return "IDORMe"

    def getUiComponent(self):
        return self._panel.component

    # ------------------------------------------------------------------
    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return None

        menu_item = JMenuItem("Send to IDORMe")

        def _action(event):
            self._panel.load_message(messages[0])
            self._callbacks.printOutput("[IDORMe] Loaded request into extension tab.")

        menu_item.addActionListener(_action)
        items = ArrayList()
        items.add(menu_item)
        return items


class IDORMePanel(object):
    """Composite UI panel implementing IDOR mutation automation."""

    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._message = None
        self._template = None
        self._http_service = None
        self._baseline_status = None
        self._baseline_length = None
        self._baseline_owner_hint = None
        self._last_user_input = None

        self.results_model = ResultsTableModel()

        self.component = JPanel(BorderLayout())
        self._controls = self._build_controls()
        self.component.add(self._controls, BorderLayout.NORTH)
        self._build_center()

    # ------------------------------------------------------------------
    def _build_controls(self):
        panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.insets = Insets(2, 2, 2, 2)
        constraints.gridy = 0
        constraints.fill = GridBagConstraints.HORIZONTAL

        self.param_field = JTextField(12)
        self.attacker_field = JTextField(10)
        self.victim_field = JTextField(10)

        constraints.gridx = 0
        panel.add(JLabel("Param"), constraints)
        constraints.gridx = 1
        panel.add(self.param_field, constraints)

        constraints.gridx = 2
        panel.add(JLabel("Attacker"), constraints)
        constraints.gridx = 3
        panel.add(self.attacker_field, constraints)

        constraints.gridx = 4
        panel.add(JLabel("Victim"), constraints)
        constraints.gridx = 5
        panel.add(self.victim_field, constraints)

        self.generate_button = JButton("Generate & Send")
        self.generate_button.addActionListener(self._start_generation)
        constraints.gridx = 6
        panel.add(self.generate_button, constraints)

        self.clear_button = JButton("Clear")
        self.clear_button.addActionListener(self._clear_results)
        constraints.gridx = 7
        panel.add(self.clear_button, constraints)

        return panel

    def _build_center(self):
        table = JTable(self.results_model)
        table.setPreferredScrollableViewportSize(Dimension(800, 300))
        table.getSelectionModel().addListSelectionListener(
            lambda event: self._on_selection(table.getSelectedRow())
        )
        self.table = table

        scroll = JScrollPane(table)
        self.request_viewer = self._callbacks.createMessageEditor(None, True)
        self.response_viewer = self._callbacks.createMessageEditor(None, False)

        lower_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        lower_split.setTopComponent(self.response_viewer.getComponent())
        lower_split.setBottomComponent(self.request_viewer.getComponent())
        lower_split.setResizeWeight(0.5)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split.setTopComponent(scroll)
        split.setBottomComponent(lower_split)
        split.setResizeWeight(0.5)

        self.component.add(split, BorderLayout.CENTER)

    # ------------------------------------------------------------------
    def load_message(self, message_info):
        try:
            template = parse_request_template(self._helpers, message_info)
        except Exception as error:  # pragma: no cover - UI feedback
            JOptionPane.showMessageDialog(
                self.component,
                "Failed to parse request: {}".format(error),
                "IDORMe",
                JOptionPane.ERROR_MESSAGE,
            )
            return

        self._message = message_info
        self._template = template
        self._http_service = message_info.getHttpService()
        self.results_model.clear()
        self.request_viewer.setMessage(message_info.getRequest(), True)
        if message_info.getResponse() is not None:
            self.response_viewer.setMessage(message_info.getResponse(), False)
            response_info = self._helpers.analyzeResponse(message_info.getResponse())
            self._baseline_status = response_info.getStatusCode()
            body = message_info.getResponse()[response_info.getBodyOffset():]
            self._baseline_length = len(body)
            self._baseline_owner_hint = self._detect_owner(body)
        else:
            self.response_viewer.setMessage(b"", False)
            self._baseline_status = None
            self._baseline_length = None
            self._baseline_owner_hint = None

    # ------------------------------------------------------------------
    def _start_generation(self, _event):
        if not self._template or not self._http_service:
            JOptionPane.showMessageDialog(
                self.component,
                "Load a request using the context menu first.",
                "IDORMe",
                JOptionPane.WARNING_MESSAGE,
            )
            return

        user_input = UserInput(
            self.param_field.getText().strip() or None,
            self.attacker_field.getText().strip() or None,
            self.victim_field.getText().strip() or None,
        )
        self._last_user_input = user_input

        worker = threading.Thread(target=self._run_generation, args=(user_input,))
        worker.daemon = True
        worker.start()

    def _run_generation(self, user_input):
        try:
            engine = MutationEngine(self._template, user_input)
            plans = engine.generate()
            results = []
            for plan in plans:
                results.append(self._execute_plan(plan, user_input))
        except Exception as error:  # pragma: no cover - background errors
            def _notify():
                JOptionPane.showMessageDialog(
                    self.component,
                    "Mutation generation failed: {}".format(error),
                    "IDORMe",
                    JOptionPane.ERROR_MESSAGE,
                )

            SwingUtilities.invokeLater(_notify)
            return

        def _update():
            self.results_model.clear()
            for result in results:
                self.results_model.add_result(result)

        SwingUtilities.invokeLater(_update)

    def _execute_plan(self, plan, user_input):
        request_bytes = plan.builder.build(self._helpers)
        response = self._callbacks.makeHttpRequest(self._http_service, request_bytes)
        response_bytes = response.getResponse() if response else None
        status_code = None
        body_length = None
        owner_hint = None
        if response_bytes:
            response_info = self._helpers.analyzeResponse(response_bytes)
            status_code = response_info.getStatusCode()
            body = response_bytes[response_info.getBodyOffset():]
            body_length = len(body)
            owner_hint = self._detect_owner(body, user_input)
        delta = None
        if self._baseline_length is not None and body_length is not None:
            delta = body_length - self._baseline_length
        return MutationResult(plan, request_bytes, response_bytes, status_code, body_length, delta, owner_hint)

    def _detect_owner(self, body, user_input=None):
        if body is None:
            return None
        if isinstance(body, bytes):
            text = body.decode("utf-8", "replace")
        else:
            text = body
        owner = None
        if user_input and user_input.victim and user_input.victim in text:
            owner = "victim"
        elif user_input and user_input.attacker and user_input.attacker in text:
            owner = "attacker"
        return owner

    def _clear_results(self, _event=None):
        self.results_model.clear()
        self.table.clearSelection()

    def _on_selection(self, index):
        if index < 0 or index >= self.results_model.row_count():
            return
        result = self.results_model.get_row(index)
        self.request_viewer.setMessage(result.request_bytes, True)
        if result.response_bytes:
            self.response_viewer.setMessage(result.response_bytes, False)
        else:
            self.response_viewer.setMessage(b"", False)


class ResultsTableModel(AbstractTableModel):
    """Swing table model storing executed mutation results."""

    COLUMNS = ["Rule", "Label", "Status", "Length", "ΔLength", "Owner"]

    def __init__(self):
        AbstractTableModel.__init__(self)
        self._rows = []

    # TableModel API ----------------------------------------------------
    def getColumnCount(self):  # noqa: N802 - Swing naming
        return len(self.COLUMNS)

    def getRowCount(self):  # noqa: N802 - Swing naming
        return len(self._rows)

    def getColumnName(self, column):  # noqa: N802 - Swing naming
        return self.COLUMNS[column]

    def getValueAt(self, row, column):  # noqa: N802 - Swing naming
        result = self._rows[row]
        if column == 0:
            return result.rule_id
        if column == 1:
            return result.label
        if column == 2:
            return result.status_code or ""
        if column == 3:
            return result.body_length or ""
        if column == 4:
            return result.delta if result.delta is not None else ""
        if column == 5:
            return result.owner_hint or ""
        return ""

    # Convenience -------------------------------------------------------
    def add_result(self, result):
        index = len(self._rows)
        self._rows.append(result)
        self.fireTableRowsInserted(index, index)

    def clear(self):
        if not self._rows:
            return
        size = len(self._rows)
        self._rows = []
        self.fireTableRowsDeleted(0, size - 1)

    def row_count(self):
        return len(self._rows)

    def get_row(self, index):
        return self._rows[index]


class MutationResult(object):
    """Stores the outcome of executing a single mutation."""

    def __init__(self, plan, request_bytes, response_bytes, status_code, body_length, delta, owner_hint):
        self.rule_id = plan.rule_id
        self.label = plan.label
        self.request_bytes = request_bytes
        self.response_bytes = response_bytes
        self.status_code = status_code
        self.body_length = body_length
        self.delta = delta
        self.owner_hint = owner_hint
