from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.gui.alerts_tab import AlertsTab
from app.gui.dashboard_tab import DashboardTab
from app.gui.settings_tab import SettingsTab
from app.gui.threat_tab import ThreatTab
from app.gui.traffic_tab import TrafficTab
from app.gui.whitelist_tab import WhitelistTab
from app.utils.config_loader import read_json
from app.utils.network_utils import get_hostname, get_local_ip_hint


class MainWindow(QMainWindow):
    def __init__(self, base_path: Path):
        super().__init__()
        self.base_path = base_path
        self.setWindowTitle("IDS Institucional")
        self.resize(1440, 900)
        self.setMinimumSize(1100, 700)

        settings = read_json(base_path / "data" / "settings.json", {})
        monitoring = bool(settings.get("monitoring_enabled", False))

        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(245)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(18, 20, 18, 20)
        sidebar_title = QLabel("IDS\nInstitucional")
        sidebar_title.setObjectName("Title")
        sidebar_layout.addWidget(sidebar_title)
        sidebar_layout.addSpacing(16)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(18, 16, 18, 18)

        header = QFrame()
        header.setObjectName("Header")
        header_layout = QHBoxLayout(header)
        title_block = QVBoxLayout()
        title = QLabel("IDS Institucional")
        title.setObjectName("Title")
        subtitle = QLabel(f"Host: {get_hostname()} | IP local: {get_local_ip_hint()} | Interfaz preparada: {settings.get('capture_interface', 'eth0')}")
        subtitle.setObjectName("Muted")
        title_block.addWidget(title)
        title_block.addWidget(subtitle)
        self.header_status = QLabel("Sistema activo" if monitoring else "Captura inactiva")
        self.header_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.header_status.setStyleSheet(f"background: {'#244f3f' if monitoring else '#4a3e23'}; border-radius: 14px; padding: 7px 14px; font-weight: 700;")
        header_layout.addLayout(title_block)
        header_layout.addStretch()
        header_layout.addWidget(self.header_status)
        content_layout.addWidget(header)

        self.stack = QStackedWidget()
        self.dashboard_page = DashboardTab(base_path)
        self.traffic_page = TrafficTab(base_path)
        self.alerts_page = AlertsTab(base_path)
        self.threat_page = ThreatTab(base_path)
        self.pages = [
            ("Dashboard", self.dashboard_page),
            ("Lista Blanca", WhitelistTab(base_path)),
            ("Trafico DNS/Sitios", self.traffic_page),
            ("Alertas", self.alerts_page),
            ("Threat Intelligence", self.threat_page),
            ("Configuracion", SettingsTab(base_path)),
        ]
        self.traffic_page.dns_event_logged.connect(self.dashboard_page.add_dns_event)
        self.traffic_page.security_alert_logged.connect(self.alerts_page.add_live_alert)
        self.traffic_page.security_alert_logged.connect(self.dashboard_page.add_alert_event)
        self.alerts_page.alert_created.connect(self.dashboard_page.add_alert_event)
        self.threat_page.alert_created.connect(self.alerts_page.add_live_alert)
        self.threat_page.alert_created.connect(self.dashboard_page.add_alert_event)
        self.traffic_page.monitoring_status_changed.connect(self.update_monitoring_status)

        self.nav_buttons: list[QPushButton] = []
        for index, (label, page) in enumerate(self.pages):
            button = QPushButton(label)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, i=index: self.switch_page(i))
            sidebar_layout.addWidget(button)
            self.nav_buttons.append(button)
            self.stack.addWidget(page)
        sidebar_layout.addStretch()

        content_layout.addWidget(self.stack)
        root_layout.addWidget(sidebar)
        root_layout.addWidget(content)
        self.setCentralWidget(root)
        self.switch_page(0)

    def switch_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        for current, button in enumerate(self.nav_buttons):
            button.setChecked(current == index)
        current_page = self.stack.currentWidget()
        if hasattr(current_page, "refresh"):
            current_page.refresh()

    def update_monitoring_status(self, status: str, interface: str) -> None:
        self.dashboard_page.set_monitoring_status(status, interface)
        if status == "Monitoreando":
            text = "Sistema activo"
            color = "#244f3f"
        elif status == "Error":
            text = "Error de captura"
            color = "#5a2626"
        else:
            text = "Captura inactiva"
            color = "#4a3e23"
        self.header_status.setText(text)
        self.header_status.setStyleSheet(f"background: {color}; border-radius: 14px; padding: 7px 14px; font-weight: 700;")

    def closeEvent(self, event) -> None:
        self.traffic_page.stop_monitoring()
        super().closeEvent(event)
