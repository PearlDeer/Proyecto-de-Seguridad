from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QGridLayout, QLabel, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from app.core.log_manager import LogManager
from app.core.whitelist_manager import WhitelistManager
from app.utils.config_loader import read_json


class MetricCard(QFrame):
    def __init__(self, title: str, value: str, subtitle: str, color: str):
        super().__init__()
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        label = QLabel(title)
        label.setObjectName("Muted")
        number = QLabel(value)
        number.setStyleSheet(f"font-size: 28px; font-weight: 800; color: {color};")
        detail = QLabel(subtitle)
        detail.setObjectName("Muted")
        layout.addWidget(label)
        layout.addWidget(number)
        layout.addWidget(detail)


class DashboardTab(QWidget):
    def __init__(self, base_path: Path):
        super().__init__()
        self.base_path = base_path
        self.logs = LogManager(base_path)
        self.whitelist = WhitelistManager(base_path)

        layout = QVBoxLayout(self)
        title = QLabel("Dashboard operativo")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)

        cards = QGridLayout()
        self.settings = read_json(base_path / "data" / "settings.json", {})
        monitoring = bool(self.settings.get("monitoring_enabled", False))
        alerts = self.logs.alert_rows()
        traffic = self.logs.traffic_rows()
        devices = self.whitelist.all_devices()

        cards.addWidget(MetricCard("Estado del IDS", "Activo" if monitoring else "Inactivo", "Monitoreo preparado", "#3fb27f" if monitoring else "#d5a93b"), 0, 0)
        cards.addWidget(MetricCard("Equipos autorizados", str(len(devices)), "Lista blanca local", "#3fb27f"), 0, 1)
        cards.addWidget(MetricCard("Alertas criticas", str(sum(1 for row in alerts if row.get("severity", "").lower() in ["critica", "alta"])), "Eventos pendientes", "#dc5b5b"), 0, 2)
        cards.addWidget(MetricCard("Dominios registrados", str(len(traffic)), "Consultas DNS en CSV", "#d5a93b"), 0, 3)
        layout.addLayout(cards)

        indicator = QLabel("Indicador de monitoreo: ACTIVO" if monitoring else "Indicador de monitoreo: INACTIVO")
        indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        indicator.setStyleSheet(f"padding: 10px; border-radius: 6px; background: {'#244f3f' if monitoring else '#4a3e23'}; font-weight: 700;")
        layout.addWidget(indicator)

        panel = QFrame()
        panel.setObjectName("Panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.addWidget(QLabel("Eventos recientes"))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Fecha", "Hora", "Severidad", "Origen", "Mensaje"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        panel_layout.addWidget(self.table)
        layout.addWidget(panel)
        self.load_events(alerts)

    def load_events(self, alerts: list[dict[str, str]]) -> None:
        self.table.setRowCount(len(alerts))
        for row, alert in enumerate(alerts):
            values = [alert.get("date", ""), alert.get("time", ""), alert.get("severity", ""), alert.get("src_ip", ""), alert.get("message", "")]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(value))
