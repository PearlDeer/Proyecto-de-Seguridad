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
        self.resize(1280, 820)
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
        status = QLabel("Sistema activo" if monitoring else "Captura inactiva")
        status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status.setStyleSheet(f"background: {'#244f3f' if monitoring else '#4a3e23'}; border-radius: 14px; padding: 7px 14px; font-weight: 700;")
        header_layout.addLayout(title_block)
        header_layout.addStretch()
        header_layout.addWidget(status)
        content_layout.addWidget(header)

        self.stack = QStackedWidget()
        self.pages = [
            ("Dashboard", DashboardTab(base_path)),
            ("Lista Blanca", WhitelistTab(base_path)),
            ("Trafico DNS/Sitios", TrafficTab(base_path)),
            ("Alertas", AlertsTab(base_path)),
            ("Threat Intelligence", ThreatTab(base_path)),
            ("Configuracion", SettingsTab(base_path)),
        ]

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
        footer = QLabel("Fase 1 | Base visual y datos locales")
        footer.setObjectName("Muted")
        footer.setWordWrap(True)
        sidebar_layout.addWidget(footer)

        content_layout.addWidget(self.stack)
        root_layout.addWidget(sidebar)
        root_layout.addWidget(content)
        self.setCentralWidget(root)
        self.switch_page(0)

    def switch_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        for current, button in enumerate(self.nav_buttons):
            button.setChecked(current == index)
