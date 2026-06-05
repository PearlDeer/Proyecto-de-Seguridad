from pathlib import Path

from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QHeaderView, QLabel, QSplitter, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget

from app.core.alert_manager import AlertManager


class AlertsTab(QWidget):
    def __init__(self, base_path: Path):
        super().__init__()
        self.manager = AlertManager(base_path)
        layout = QVBoxLayout(self)
        splitter = QSplitter()
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Fecha", "Hora", "Severidad", "IP origen", "IP destino", "Mensaje"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        detail_panel = QWidget()
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.addWidget(QLabel("Detalle de alerta"))
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        detail_layout.addWidget(self.detail)
        splitter.addWidget(self.table)
        splitter.addWidget(detail_panel)
        splitter.setSizes([760, 320])
        layout.addWidget(splitter)
        self.table.itemSelectionChanged.connect(self.show_detail)
        self.load_rows()

    def load_rows(self) -> None:
        self.rows = self.manager.alerts()
        self.table.setRowCount(len(self.rows))
        for row_index, row in enumerate(self.rows):
            values = [row.get("date", ""), row.get("time", ""), row.get("severity", ""), row.get("src_ip", ""), row.get("dst_ip", ""), row.get("message", "")]
            color = self.severity_color(row.get("severity", ""))
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 2:
                    item.setBackground(QColor(color))
                self.table.setItem(row_index, column, item)

    def show_detail(self) -> None:
        items = self.table.selectedItems()
        if not items:
            return
        row = self.rows[items[0].row()]
        self.detail.setPlainText("\n".join(f"{key}: {value}" for key, value in row.items()))

    def severity_color(self, severity: str) -> str:
        normalized = severity.lower()
        if normalized in ["critica", "alta"]:
            return "#6b2d2d"
        if normalized in ["media", "advertencia"]:
            return "#6b5524"
        return "#2d5b46"
