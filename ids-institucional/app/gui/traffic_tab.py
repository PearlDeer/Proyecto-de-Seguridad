from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.log_manager import LogManager
from app.core.packet_sniffer import PacketSniffer
from app.utils.config_loader import read_json, write_json
from app.utils.network_utils import list_network_interfaces


class TrafficTab(QWidget):
    dns_event_logged = pyqtSignal(dict)
    security_alert_logged = pyqtSignal(dict)
    monitoring_status_changed = pyqtSignal(str, str)
    event_received = pyqtSignal(dict)
    alert_received = pyqtSignal(dict)
    capture_error = pyqtSignal(str)

    def __init__(self, base_path: Path):
        super().__init__()
        self.base_path = base_path
        self.settings_path = base_path / "data" / "settings.json"
        self.logs = LogManager(base_path)
        self.sniffer: PacketSniffer | None = None
        self.event_count = 0
        self.current_status = "Detenido"

        self.event_received.connect(self.handle_dns_event)
        self.alert_received.connect(self.handle_security_alert)
        self.capture_error.connect(self.handle_capture_error)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel("Monitoreo de Sitios y Consultas DNS")
        title.setObjectName("SectionTitle")
        subtitle = QLabel("Visualizacion en tiempo real de dominios consultados por los equipos de la red")
        subtitle.setObjectName("Muted")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        status_panel = QFrame()
        status_panel.setObjectName("Panel")
        status_layout = QGridLayout(status_panel)
        self.status_label = self._status_value("Estado", "Detenido", "#aeb6c2")
        self.interface_label = self._status_value("Interfaz de red activa", "-", "#d5a93b")
        self.total_label = self._status_value("Total de eventos capturados", "0", "#3fb27f")
        self.last_event_label = self._status_value("Ultimo evento", "Sin eventos", "#aeb6c2")
        status_layout.addWidget(self.status_label, 0, 0)
        status_layout.addWidget(self.interface_label, 0, 1)
        status_layout.addWidget(self.total_label, 0, 2)
        status_layout.addWidget(self.last_event_label, 0, 3)
        layout.addWidget(status_panel)

        controls = QHBoxLayout()
        self.interface_selector = QComboBox()
        self.reload_interfaces()
        self.start_button = QPushButton("Iniciar monitoreo")
        self.stop_button = QPushButton("Detener monitoreo")
        self.reload_button = QPushButton("Recargar CSV")
        self.clear_button = QPushButton("Limpiar vista")
        self.test_button = QPushButton("Generar evento de prueba")
        controls.addWidget(QLabel("Interfaz:"))
        controls.addWidget(self.interface_selector, 1)
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        controls.addWidget(self.reload_button)
        controls.addWidget(self.clear_button)
        controls.addWidget(self.test_button)
        layout.addLayout(controls)

        activity = QFrame()
        activity.setObjectName("Panel")
        activity_layout = QGridLayout(activity)
        activity_title = QLabel("Ultima actividad")
        activity_title.setObjectName("SectionTitle")
        self.last_domain = QLabel("-")
        self.last_ip = QLabel("-")
        self.last_time = QLabel("-")
        self.last_state = QLabel("Detenido")
        for label in [self.last_domain, self.last_ip, self.last_time, self.last_state]:
            label.setWordWrap(True)
        activity_layout.addWidget(activity_title, 0, 0, 1, 4)
        activity_layout.addWidget(QLabel("Dominio mas reciente"), 1, 0)
        activity_layout.addWidget(QLabel("IP origen"), 1, 1)
        activity_layout.addWidget(QLabel("Hora"), 1, 2)
        activity_layout.addWidget(QLabel("Estado"), 1, 3)
        activity_layout.addWidget(self.last_domain, 2, 0)
        activity_layout.addWidget(self.last_ip, 2, 1)
        activity_layout.addWidget(self.last_time, 2, 2)
        activity_layout.addWidget(self.last_state, 2, 3)
        layout.addWidget(activity)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Hora", "IP origen", "MAC origen", "Dominio", "Protocolo", "Evento"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table, 1)

        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.reload_button.clicked.connect(self.load_rows)
        self.clear_button.clicked.connect(lambda: self.table.setRowCount(0))
        self.test_button.clicked.connect(self.generate_test_event)

        self.load_rows()
        self.update_status("Detenido")

    def _status_value(self, title: str, value: str, color: str) -> QLabel:
        label = QLabel(f"{title}\n{value}")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet(f"font-weight: 700; color: {color}; padding: 8px;")
        return label

    def reload_interfaces(self) -> None:
        settings = read_json(self.settings_path, {})
        configured = settings.get("capture_interface", "")
        interfaces = list_network_interfaces()
        if configured and configured not in interfaces:
            interfaces.insert(0, configured)
        if not interfaces:
            interfaces = ["eth0"]
        self.interface_selector.clear()
        self.interface_selector.addItems(interfaces)
        if configured:
            index = self.interface_selector.findText(configured)
            if index >= 0:
                self.interface_selector.setCurrentIndex(index)

    def start_monitoring(self) -> None:
        interface = self.interface_selector.currentText().strip()
        if not interface:
            self.handle_capture_error("Seleccione una interfaz de red valida para iniciar la captura.")
            return

        self.stop_monitoring(update_settings=False)
        self.sniffer = PacketSniffer(
            interface,
            self.event_received.emit,
            self.capture_error.emit,
            alert_callback=self.alert_received.emit,
            base_path=self.base_path,
        )
        self.sniffer.start()
        self.update_status("Monitoreando", interface)
        self._save_monitoring_settings(interface, True)

    def stop_monitoring(self, update_settings: bool = True) -> None:
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        interface = self.interface_selector.currentText().strip()
        self.update_status("Detenido", interface)
        if update_settings:
            self._save_monitoring_settings(interface, False)

    def handle_capture_error(self, message: str) -> None:
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        self.update_status("Error", self.interface_selector.currentText().strip(), message)
        self._save_monitoring_settings(self.interface_selector.currentText().strip(), False)

    def handle_dns_event(self, event: dict[str, str]) -> None:
        domain = event.get("domain", "").strip()
        if not domain:
            return
        self.logs.log_dns_event(event)
        self.insert_event(event)
        self.dns_event_logged.emit(event)

    def handle_security_alert(self, alert: dict[str, str]) -> None:
        self.security_alert_logged.emit(alert)

    def generate_test_event(self) -> None:
        self.handle_dns_event(self.logs.build_test_dns_event())

    def insert_event(self, event: dict[str, str]) -> None:
        self.table.insertRow(0)
        values = [
            event.get("time", ""),
            event.get("src_ip", ""),
            event.get("src_mac", ""),
            event.get("domain", ""),
            event.get("protocol", ""),
            event.get("event_type", ""),
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            if column == 3:
                item.setForeground(Qt.GlobalColor.cyan)
            self.table.setItem(0, column, item)

        self.event_count += 1
        self.total_label.setText(f"Total de eventos capturados\n{self.event_count}")
        self.last_event_label.setText(f"Ultimo evento\n{event.get('time', '')} - {event.get('domain', '')}")
        self.last_domain.setText(event.get("domain", "-"))
        self.last_ip.setText(event.get("src_ip", "-"))
        self.last_time.setText(event.get("time", "-"))
        self.last_state.setText(self.current_status)

    def load_rows(self) -> None:
        rows = self.logs.traffic_rows()
        self.table.setRowCount(0)
        for row in reversed(rows[-500:]):
            self.insert_event(row)
        self.event_count = len(rows)
        self.total_label.setText(f"Total de eventos capturados\n{self.event_count}")

    def update_status(self, status: str, interface: str | None = None, message: str | None = None) -> None:
        self.current_status = status
        interface = interface or self.interface_selector.currentText().strip() or "-"
        colors = {"Monitoreando": "#3fb27f", "Detenido": "#aeb6c2", "Error": "#dc5b5b"}
        color = colors.get(status, "#aeb6c2")
        self.status_label.setText(f"Estado\n{status}")
        self.status_label.setStyleSheet(f"font-weight: 800; color: {color}; padding: 8px;")
        self.interface_label.setText(f"Interfaz de red activa\n{interface}")
        self.last_state.setText(message or status)
        self.monitoring_status_changed.emit(status, interface)

    def _save_monitoring_settings(self, interface: str, enabled: bool) -> None:
        settings = read_json(self.settings_path, {})
        settings["capture_interface"] = interface
        settings["monitoring_enabled"] = enabled
        write_json(self.settings_path, settings)

    def closeEvent(self, event) -> None:
        self.stop_monitoring()
        super().closeEvent(event)
