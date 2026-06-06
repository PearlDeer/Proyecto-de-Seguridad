from datetime import datetime, timedelta
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QGridLayout, QLabel, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from app.core.log_manager import LogManager
from app.core.threat_intel import ThreatIntelService
from app.core.whitelist_manager import WhitelistManager
from app.utils.config_loader import read_json


class MetricCard(QFrame):
    def __init__(self, title: str, value: str, subtitle: str, color: str):
        super().__init__()
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        title_label = QLabel(title)
        title_label.setObjectName("Muted")
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"font-size: 28px; font-weight: 800; color: {color};")
        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("Muted")
        self.subtitle_label.setWordWrap(True)
        layout.addWidget(title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.subtitle_label)

    def set_value(self, value: str, color: str | None = None, subtitle: str | None = None) -> None:
        self.value_label.setText(value)
        if color:
            self.value_label.setStyleSheet(f"font-size: 28px; font-weight: 800; color: {color};")
        if subtitle is not None:
            self.subtitle_label.setText(subtitle)


class DashboardTab(QWidget):
    def __init__(self, base_path: Path):
        super().__init__()
        self.base_path = base_path
        self.logs = LogManager(base_path)
        self.whitelist = WhitelistManager(base_path)
        self.threat_intel = ThreatIntelService(base_path)
        self.runtime_status = ""
        self.runtime_interface = ""

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        title = QLabel("Dashboard operativo")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)

        self.status_banner = QLabel()
        self.status_banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_banner.setMinimumHeight(54)
        layout.addWidget(self.status_banner)

        cards = QGridLayout()
        self.domains_card = MetricCard("Eventos DNS registrados", "0", "Consultas en traffic_log.csv", "#3fb27f")
        self.authorized_card = MetricCard("Equipos autorizados", "0", "Lista blanca IP/MAC", "#7fb3d5")
        self.alerts_total_card = MetricCard("Alertas totales", "0", "Eventos en alerts_log.csv", "#d5a93b")
        self.alerts_card = MetricCard("Alertas criticas", "0", "CRITICAL y EMERGENCY", "#dc5b5b")
        self.blacklist_card = MetricCard("IPs peligrosas cargadas", "0", "Blacklist local", "#ff8f70")
        self.rate_card = MetricCard("Eventos por minuto", "0", "Ventana movil de 60 segundos", "#7fb3d5")
        cards.addWidget(self.authorized_card, 0, 0)
        cards.addWidget(self.domains_card, 0, 1)
        cards.addWidget(self.alerts_total_card, 0, 2)
        cards.addWidget(self.alerts_card, 0, 3)
        cards.addWidget(self.blacklist_card, 1, 0)
        cards.addWidget(self.rate_card, 1, 1)
        layout.addLayout(cards)

        activity_panel = QFrame()
        activity_panel.setObjectName("Panel")
        activity_layout = QGridLayout(activity_panel)
        activity_title = QLabel("Actividad reciente")
        activity_title.setObjectName("SectionTitle")
        self.last_domain = QLabel("-")
        self.last_ip = QLabel("-")
        self.last_time = QLabel("-")
        self.last_alert = QLabel("-")
        self.last_forensic = QLabel("-")
        for label in [self.last_domain, self.last_ip, self.last_time, self.last_alert, self.last_forensic]:
            label.setWordWrap(True)
        activity_layout.addWidget(activity_title, 0, 0, 1, 5)
        activity_layout.addWidget(QLabel("Ultimo dominio detectado"), 1, 0)
        activity_layout.addWidget(QLabel("Ultima IP origen detectada"), 1, 1)
        activity_layout.addWidget(QLabel("Ultima alerta"), 1, 2)
        activity_layout.addWidget(QLabel("Ultimo evento forense"), 1, 3)
        activity_layout.addWidget(QLabel("Hora DNS"), 1, 4)
        activity_layout.addWidget(self.last_domain, 2, 0)
        activity_layout.addWidget(self.last_ip, 2, 1)
        activity_layout.addWidget(self.last_alert, 2, 2)
        activity_layout.addWidget(self.last_forensic, 2, 3)
        activity_layout.addWidget(self.last_time, 2, 4)
        layout.addWidget(activity_panel)

        timeline_panel = QFrame()
        timeline_panel.setObjectName("Panel")
        timeline_layout = QVBoxLayout(timeline_panel)
        timeline_title = QLabel("Timeline de ultimos eventos")
        timeline_title.setObjectName("SectionTitle")
        timeline_layout.addWidget(timeline_title)
        self.timeline = QTableWidget(0, 4)
        self.timeline.setHorizontalHeaderLabels(["Hora", "Tipo", "Origen", "Detalle"])
        self.timeline.horizontalHeader().setStretchLastSection(True)
        self.timeline.setAlternatingRowColors(True)
        self.timeline.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        timeline_layout.addWidget(self.timeline)
        layout.addWidget(timeline_panel, 1)

        self.refresh()

    def refresh(self) -> None:
        settings = read_json(self.base_path / "data" / "settings.json", {})
        status = self.runtime_status or ("Activo" if settings.get("monitoring_enabled", False) else "Detenido")
        interface = self.runtime_interface or settings.get("capture_interface", "-")
        traffic = self.logs.traffic_rows()
        alerts = self.logs.alert_rows()
        forensic = self.logs.forensic_rows()

        self.set_monitoring_status(status, interface)
        self.update_metrics(traffic, alerts, forensic)
        self.load_timeline(traffic[-8:], alerts[-8:], forensic[-8:])

    def set_monitoring_status(self, status: str, interface: str = "") -> None:
        self.runtime_status = status
        self.runtime_interface = interface
        normalized = status.lower()
        if normalized in ["activo", "monitoreando"]:
            color = "#244f3f"
            text = "IDS ACTIVO"
        elif normalized == "error":
            color = "#5a2626"
            text = "IDS EN ERROR"
        else:
            color = "#3a4049"
            text = "IDS DETENIDO"
        suffix = f" | Interfaz: {interface}" if interface else ""
        self.status_banner.setText(f"{text}{suffix}")
        self.status_banner.setStyleSheet(f"background: {color}; border-radius: 8px; font-size: 22px; font-weight: 800;")

    def update_metrics(self, traffic: list[dict[str, str]], alerts: list[dict[str, str]], forensic: list[dict[str, str]]) -> None:
        critical_alerts = sum(1 for row in alerts if row.get("severity", "").upper() in ["CRITICAL", "EMERGENCY", "CRITICA", "ALTA"])
        events_per_minute = self._events_per_minute(traffic)

        self.authorized_card.set_value(str(len(self.whitelist.all_devices())), "#7fb3d5")
        self.domains_card.set_value(str(len(traffic)), "#3fb27f")
        self.alerts_total_card.set_value(str(len(alerts)), "#d5a93b")
        self.alerts_card.set_value(str(critical_alerts), "#dc5b5b")
        self.blacklist_card.set_value(str(len(self.threat_intel.indicators())), "#ff8f70")
        self.rate_card.set_value(str(events_per_minute), "#7fb3d5")

        if traffic:
            last = traffic[-1]
            self.last_domain.setText(last.get("domain", "-"))
            self.last_ip.setText(last.get("src_ip", "-"))
            self.last_time.setText(f"{last.get('date', '')} {last.get('time', '')}".strip())
        else:
            self.last_domain.setText("-")
            self.last_ip.setText("-")
            self.last_time.setText("-")
        self.last_alert.setText(alerts[-1].get("risk_type", "-") if alerts else "-")
        if forensic:
            last_forensic = forensic[-1]
            self.last_forensic.setText(f"{last_forensic.get('ip', '-')} | {last_forensic.get('abuse_contact', '-')}")
        else:
            self.last_forensic.setText("-")

    def load_timeline(self, traffic_rows: list[dict[str, str]], alert_rows: list[dict[str, str]], forensic_rows: list[dict[str, str]]) -> None:
        events: list[dict[str, str]] = []
        for row in traffic_rows:
            events.append(
                {
                    "date": row.get("date", ""),
                    "time": row.get("time", ""),
                    "type": "DNS",
                    "origin": row.get("src_ip", ""),
                    "detail": row.get("domain", ""),
                }
            )
        for row in alert_rows:
            events.append(
                {
                    "date": row.get("date", ""),
                    "time": row.get("time", ""),
                    "type": row.get("severity", "ALERTA"),
                    "origin": row.get("src_ip", ""),
                    "detail": row.get("risk_type", ""),
                }
            )
        for row in forensic_rows:
            events.append(
                {
                    "date": row.get("date", ""),
                    "time": row.get("time", ""),
                    "type": "WHOIS",
                    "origin": row.get("ip", ""),
                    "detail": row.get("abuse_contact", ""),
                }
            )
        recent = sorted(events, key=lambda item: f"{item.get('date', '')} {item.get('time', '')}", reverse=True)[:12]
        self.timeline.setRowCount(len(recent))
        for row_index, row in enumerate(recent):
            values = [row.get("time", ""), row.get("type", ""), row.get("origin", ""), row.get("detail", "")]
            for column, value in enumerate(values):
                self.timeline.setItem(row_index, column, QTableWidgetItem(value))

    def add_dns_event(self, event: dict[str, str]) -> None:
        self.refresh()

    def add_alert_event(self, event: dict[str, str]) -> None:
        self.refresh()

    def _events_per_minute(self, rows: list[dict[str, str]]) -> int:
        now = datetime.now()
        cutoff = now - timedelta(seconds=60)
        count = 0
        for row in rows:
            try:
                event_time = datetime.strptime(f"{row.get('date')} {row.get('time')}", "%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError):
                continue
            if event_time >= cutoff:
                count += 1
        return count
