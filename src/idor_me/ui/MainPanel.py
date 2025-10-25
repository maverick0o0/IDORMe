"""Swing UI for the IDORMe extension."""

try:
    from javax.swing import (  # type: ignore
        BorderFactory,
        JButton,
        JCheckBox,
        JFileChooser,
        JLabel,
        JPanel,
        JScrollPane,
        JSpinner,
        JTable,
        JTextField,
        SwingUtilities,
        SpinnerNumberModel,
        DefaultTableModel,
    )
    from java.awt import BorderLayout, GridBagConstraints, GridBagLayout, Insets  # type: ignore
    from java.awt.event import MouseAdapter  # type: ignore
    SWING_AVAILABLE = True
except Exception:  # pragma: no cover - tests
    SWING_AVAILABLE = False

from ..core.executor import ExecutionOptions


class _FallbackPanel(object):
    def __init__(self):
        self._results = []

    def getComponent(self):
        return self

    def get_user_inputs(self):
        return {"name": None, "attacker": None, "victim": None}

    def get_execution_options(self):
        return ExecutionOptions()

    def display_result(self, result):
        self._results.append(result)

    def clear_results(self):
        self._results = []

    def set_run_handler(self, handler):
        self._run_handler = handler

    def set_stop_handler(self, handler):
        self._stop_handler = handler

    def set_clear_handler(self, handler):
        self._clear_handler = handler

    def set_export_handler(self, handler):
        self._export_handler = handler

    def set_row_handler(self, handler):
        self._row_handler = handler

    def run_last(self):
        if hasattr(self, "_run_handler"):
            self._run_handler()

    def stop(self):
        if hasattr(self, "_stop_handler"):
            self._stop_handler()

    def clear(self):
        if hasattr(self, "_clear_handler"):
            self._clear_handler()

    def export_csv(self):
        if hasattr(self, "_export_handler"):
            self._export_handler(None)


class MainPanel(object):
    def __init__(self, mutator, executor):
        self._mutator = mutator
        self._executor = executor
        self._results = []
        self._row_handler = None
        self._run_handler = None
        self._stop_handler = None
        self._clear_handler = None
        self._export_handler = None
        if not SWING_AVAILABLE:
            self._component = _FallbackPanel()
            return
        self._build_ui()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def getComponent(self):
        return self._component

    def get_user_inputs(self):
        if not SWING_AVAILABLE:
            return self._component.get_user_inputs()
        return {
            "name": self._param_name.getText().strip() or None,
            "attacker": self._attacker_value.getText().strip() or None,
            "victim": self._victim_value.getText().strip() or None,
        }

    def get_execution_options(self):
        if not SWING_AVAILABLE:
            return self._component.get_execution_options()
        return ExecutionOptions(
            safe_mode=self._safe_mode.isSelected(),
            follow_redirects=self._follow_redirects.isSelected(),
            concurrency=self._concurrency_spinner.getValue(),
            timeout=self._timeout_spinner.getValue(),
            apply_global=self._apply_global.isSelected(),
            apply_specific=self._apply_specific.isSelected(),
        )

    def display_result(self, result):
        if not SWING_AVAILABLE:
            self._component.display_result(result)
            return
        self._results.append(result)
        owner = result["owner"]
        owner_text = owner["label"]
        if owner["score"]:
            owner_text += " (%d)" % owner["score"]
        row = [
            result["#"],
            result["rule_id"],
            result["method"],
            result["url"],
            result["content_type"],
            result["request_size"],
            result["status"],
            result["length"],
            result["delta_len"],
            result["hash"],
            owner_text,
            result["note"],
        ]
        SwingUtilities.invokeLater(_RunLater(lambda: self._table_model.addRow(row)))

    def clear_results(self):
        if not SWING_AVAILABLE:
            self._component.clear_results()
            return
        self._results = []
        def _clear():
            while self._table_model.getRowCount() > 0:
                self._table_model.removeRow(0)
        SwingUtilities.invokeLater(_RunLater(_clear))

    def set_run_handler(self, handler):
        if not SWING_AVAILABLE:
            self._component.set_run_handler(handler)
            return
        self._run_handler = handler

    def set_stop_handler(self, handler):
        if not SWING_AVAILABLE:
            self._component.set_stop_handler(handler)
            return
        self._stop_handler = handler

    def set_clear_handler(self, handler):
        if not SWING_AVAILABLE:
            self._component.set_clear_handler(handler)
            return
        self._clear_handler = handler

    def set_export_handler(self, handler):
        if not SWING_AVAILABLE:
            self._component.set_export_handler(handler)
            return
        self._export_handler = handler

    def set_row_handler(self, handler):
        if not SWING_AVAILABLE:
            self._component.set_row_handler(handler)
            return
        self._row_handler = handler

    def export_csv(self, parent):
        if not SWING_AVAILABLE:
            self._component.export_csv()
            return
        chooser = JFileChooser()
        if chooser.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            self._write_csv(file_path)

    def results(self):
        return list(self._results)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self):
        self._component = JPanel(BorderLayout())
        self._component.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        self._component.add(self._build_controls(), BorderLayout.NORTH)
        self._component.add(self._build_table(), BorderLayout.CENTER)

    def _build_controls(self):
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(2, 2, 2, 2)
        gbc.gridx = 0
        gbc.gridy = 0
        panel.add(JLabel("Param name"), gbc)
        gbc.gridx = 1
        self._param_name = JTextField(12)
        panel.add(self._param_name, gbc)
        gbc.gridx = 2
        panel.add(JLabel("Attacker value"), gbc)
        gbc.gridx = 3
        self._attacker_value = JTextField(10)
        panel.add(self._attacker_value, gbc)
        gbc.gridx = 4
        panel.add(JLabel("Victim value"), gbc)
        gbc.gridx = 5
        self._victim_value = JTextField(10)
        panel.add(self._victim_value, gbc)

        gbc.gridy = 1
        gbc.gridx = 0
        self._safe_mode = JCheckBox("Safe Mode", True)
        panel.add(self._safe_mode, gbc)
        gbc.gridx = 1
        self._follow_redirects = JCheckBox("Follow redirects", False)
        panel.add(self._follow_redirects, gbc)
        gbc.gridx = 2
        panel.add(JLabel("Concurrency"), gbc)
        gbc.gridx = 3
        self._concurrency_spinner = JSpinner(SpinnerNumberModel(6, 1, 32, 1))
        panel.add(self._concurrency_spinner, gbc)
        gbc.gridx = 4
        panel.add(JLabel("Timeout (s)"), gbc)
        gbc.gridx = 5
        self._timeout_spinner = JSpinner(SpinnerNumberModel(10, 1, 120, 1))
        panel.add(self._timeout_spinner, gbc)

        gbc.gridy = 2
        gbc.gridx = 0
        self._apply_global = JCheckBox("Apply Global rules", True)
        panel.add(self._apply_global, gbc)
        gbc.gridx = 1
        self._apply_specific = JCheckBox("Apply Specific rules", True)
        panel.add(self._apply_specific, gbc)

        gbc.gridy = 3
        gbc.gridx = 0
        run_btn = JButton("Run All")
        run_btn.addActionListener(lambda event: self._run_handler and self._run_handler())
        panel.add(run_btn, gbc)
        gbc.gridx = 1
        stop_btn = JButton("Stop")
        stop_btn.addActionListener(lambda event: self._stop_handler and self._stop_handler())
        panel.add(stop_btn, gbc)
        gbc.gridx = 2
        clear_btn = JButton("Clear")
        clear_btn.addActionListener(lambda event: self._clear_handler and self._clear_handler())
        panel.add(clear_btn, gbc)
        gbc.gridx = 3
        export_btn = JButton("Export CSV")
        export_btn.addActionListener(lambda event: self._export_handler and self._export_handler(self._component))
        panel.add(export_btn, gbc)
        return panel

    def _build_table(self):
        columns = ["#", "RuleID", "Method", "URL/Path", "CT", "Req Size", "Resp Code",
                   "Resp Len", "ΔLen", "Hash (first 8)", "OwnerScore", "Notes"]
        self._table_model = DefaultTableModel([], columns)
        table = JTable(self._table_model)
        table.setFillsViewportHeight(True)
        table.addMouseListener(_TableListener(self))
        scroll = JScrollPane(table)
        return scroll

    def _write_csv(self, file_path):
        try:
            import csv
            rows = self.results()
            with open(file_path, "w") as handle:
                writer = csv.writer(handle)
                writer.writerow(["#", "RuleID", "Method", "URL", "Content-Type", "RequestSize",
                                 "ResponseCode", "ResponseLength", "DeltaLength", "Hash", "Owner", "Notes"])
                for result in rows:
                    owner = result["owner"]["label"]
                    if result["owner"]["score"]:
                        owner = "%s (%d)" % (owner, result["owner"]["score"])
                    writer.writerow([
                        result["#"], result["rule_id"], result["method"], result["url"],
                        result["content_type"], result["request_size"], result["status"],
                        result["length"], result["delta_len"], result["hash"], owner, result["note"],
                    ])
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Event helpers
    # ------------------------------------------------------------------
    def handle_row_open(self, index):
        if not self._row_handler:
            return
        if index < 0 or index >= len(self._results):
            return
        self._row_handler(self._results[index])


if SWING_AVAILABLE:

    class _RunLater(object):
        def __init__(self, func):
            self._func = func

        def run(self):  # pragma: no cover - Swing bridge
            self._func()


    class _TableListener(MouseAdapter):
        def __init__(self, panel):
            self._panel = panel

        def mouseClicked(self, event):  # pragma: no cover - UI callback
            if event.getClickCount() == 2:
                table = event.getSource()
                row = table.getSelectedRow()
                self._panel.handle_row_open(row)

else:

    class _RunLater(object):
        def __init__(self, func):
            self._func = func

        def run(self):
            self._func()


    class _TableListener(object):
        def __init__(self, panel):
            self._panel = panel

        def mouseClicked(self, event):
            pass


__all__ = ["MainPanel"]
