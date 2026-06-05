from pathlib import Path
import subprocess

from PyQt6.QtWidgets import QHBoxLayout, QHeaderView, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from app.core.log_manager import LogManager


class TrafficTab(QWidget):
    def __init__(self, base_path: Path):
        super().__init__()
        self.logs = LogManager(base_path)
        layout = QVBoxLayout(self)
        buttons = QHBoxLayout()
        self.clear_button = QPushButton("Limpiar vista")
        self.open_button = QPushButton("Abrir CSV")
        buttons.addWidget(self.clear_button)
        buttons.addWidget(self.open_button)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Fecha", "Hora", "IP origen", "Dominio", "Tipo"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)
        self.clear_button.clicked.connect(lambda: self.table.setRowCount(0))
        self.open_button.clicked.connect(self.open_csv)
        self.load_rows()

    def open_csv(self) -> None:
        try:
            subprocess.Popen(["xdg-open", str(self.logs.traffic_path)])
        except OSError:
            pass

    def load_rows(self) -> None:
        rows = self.logs.traffic_rows()
        self.table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            values = [row.get("date", ""), row.get("time", ""), row.get("src_ip", ""), row.get("domain", ""), row.get("event_type", "")]
            for column, value in enumerate(values):
                self.table.setItem(row_index, column, QTableWidgetItem(value))
