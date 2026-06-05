from pathlib import Path

from PyQt6.QtWidgets import QHBoxLayout, QHeaderView, QInputDialog, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from app.core.threat_intel import ThreatIntelService


class ThreatTab(QWidget):
    def __init__(self, base_path: Path):
        super().__init__()
        self.service = ThreatIntelService(base_path)
        layout = QVBoxLayout(self)
        buttons = QHBoxLayout()
        self.reload_button = QPushButton("Recargar blacklist")
        self.test_button = QPushButton("Probar consulta")
        buttons.addWidget(self.reload_button)
        buttons.addWidget(self.test_button)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["IP", "Riesgo", "Fuente", "Descripcion"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)
        self.reload_button.clicked.connect(self.load_rows)
        self.test_button.clicked.connect(self.test_lookup)
        self.load_rows()

    def load_rows(self) -> None:
        rows = self.service.indicators()
        self.table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            values = [row.get("ip", ""), row.get("severity", ""), row.get("source", ""), row.get("description", "")]
            for column, value in enumerate(values):
                self.table.setItem(row_index, column, QTableWidgetItem(value))

    def test_lookup(self) -> None:
        ip, accepted = QInputDialog.getText(self, "Consulta local", "IP a consultar:")
        if not accepted:
            return
        result = self.service.lookup_local(ip)
        if result.get("found"):
            indicator = result["indicator"]
            QMessageBox.warning(self, "Indicador encontrado", f"{indicator['ip']} - {indicator['risk_type']} ({indicator['severity']})")
        else:
            QMessageBox.information(self, "Consulta local", result.get("message", "Sin coincidencias."))
