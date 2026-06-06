from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.alert_manager import AlertManager
from app.core.forensic_lookup import ForensicLookupService, NO_ABUSE_CONTACT


class AlertMetricCard(QFrame):
    def __init__(self, title: str, value: str, color: str):
        super().__init__()
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        label = QLabel(title)
        label.setObjectName("Muted")
        self.value = QLabel(value)
        self.value.setStyleSheet(f"font-size: 24px; font-weight: 800; color: {color};")
        self.value.setWordWrap(True)
        layout.addWidget(label)
        layout.addWidget(self.value)


class AlertsTab(QWidget):
    alert_created = pyqtSignal(dict)

    def __init__(self, base_path: Path):
        super().__init__()
        self.base_path = base_path
        self.manager = AlertManager(base_path)
        self.forensic = ForensicLookupService(base_path)
        self.rows: list[dict[str, str]] = []

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        title = QLabel("Centro de Alertas del IDS")
        title.setObjectName("SectionTitle")
        subtitle = QLabel("Eventos de seguridad detectados en tiempo real")
        subtitle.setObjectName("Muted")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        cards = QGridLayout()
        self.total_card = AlertMetricCard("Total de alertas", "0", "#d5a93b")
        self.critical_card = AlertMetricCard("Criticas", "0", "#dc5b5b")
        self.emergency_card = AlertMetricCard("Emergencias", "0", "#ff8f70")
        self.last_card = AlertMetricCard("Ultima alerta", "-", "#aeb6c2")
        cards.addWidget(self.total_card, 0, 0)
        cards.addWidget(self.critical_card, 0, 1)
        cards.addWidget(self.emergency_card, 0, 2)
        cards.addWidget(self.last_card, 0, 3)
        layout.addLayout(cards)

        buttons = QHBoxLayout()
        self.reload_button = QPushButton("Recargar alertas")
        self.clear_button = QPushButton("Limpiar vista")
        self.review_button = QPushButton("Marcar como revisada")
        self.whois_button = QPushButton("Consultar WHOIS nuevamente")
        self.test_unknown_button = QPushButton("Generar alerta equipo no autorizado")
        self.test_blacklist_button = QPushButton("Generar alerta IP peligrosa")
        buttons.addWidget(self.reload_button)
        buttons.addWidget(self.clear_button)
        buttons.addWidget(self.review_button)
        buttons.addWidget(self.whois_button)
        buttons.addWidget(self.test_unknown_button)
        buttons.addWidget(self.test_blacklist_button)
        buttons.addStretch()
        layout.addLayout(buttons)

        splitter = QSplitter()
        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["Fecha", "Hora", "Severidad", "IP origen", "MAC origen", "IP destino", "Riesgo", "Estado"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        detail_panel = QFrame()
        detail_panel.setObjectName("Panel")
        detail_layout = QVBoxLayout(detail_panel)
        detail_title = QLabel("Detalle de alerta seleccionada")
        detail_title.setObjectName("SectionTitle")
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        detail_layout.addWidget(detail_title)
        detail_layout.addWidget(self.detail)

        splitter.addWidget(self.table)
        splitter.addWidget(detail_panel)
        splitter.setSizes([820, 360])
        layout.addWidget(splitter, 1)

        self.reload_button.clicked.connect(self.load_rows)
        self.clear_button.clicked.connect(lambda: self.table.setRowCount(0))
        self.review_button.clicked.connect(self.mark_selected_reviewed)
        self.whois_button.clicked.connect(self.lookup_selected_whois)
        self.test_unknown_button.clicked.connect(self.generate_test_unauthorized)
        self.test_blacklist_button.clicked.connect(self.generate_test_blacklist)
        self.table.itemSelectionChanged.connect(self.show_detail)
        self.load_rows()

    def load_rows(self) -> None:
        self.rows = self.manager.alerts()
        self.table.setRowCount(0)
        for row in self.rows[-500:]:
            self.insert_alert(row, persist=False)
        self.update_cards()

    def insert_alert(self, alert: dict[str, str], persist: bool = False) -> None:
        if persist:
            self.rows.append(alert)
        self.table.insertRow(0)
        values = [
            alert.get("date", ""),
            alert.get("time", ""),
            alert.get("severity", ""),
            alert.get("src_ip", ""),
            alert.get("src_mac", ""),
            alert.get("dst_ip", ""),
            alert.get("risk_type", ""),
            alert.get("status", ""),
        ]
        row_color = self.severity_color(alert.get("severity", ""))
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            if column == 2:
                item.setBackground(QColor(row_color))
                item.setForeground(QColor("#ffffff"))
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(0, column, item)
        self.update_cards()

    def show_detail(self) -> None:
        row = self.selected_alert()
        if not row:
            return
        self.detail.setPlainText(self.build_alert_detail(row))

    def mark_selected_reviewed(self) -> None:
        alert = self.selected_alert()
        if not alert:
            QMessageBox.information(self, "Alertas", "Seleccione una alerta para marcarla como revisada.")
            return
        self.manager.mark_reviewed(alert)
        self.load_rows()

    def lookup_selected_whois(self) -> None:
        alert = self.selected_alert()
        if not alert or not alert.get("dst_ip"):
            QMessageBox.information(self, "WHOIS", "Seleccione una alerta con IP destino.")
            return
        result = self.forensic.lookup_ip(alert["dst_ip"])
        self.detail.setPlainText(self.build_alert_detail(alert, result))
        QMessageBox.information(self, "WHOIS", "Consulta WHOIS finalizada y guardada en forensic_log.csv.")

    def selected_alert(self) -> dict[str, str] | None:
        selected = self.table.selectedItems()
        if not selected:
            return None
        visible_row = selected[0].row()
        visible_rows = list(reversed(self.rows[-500:]))
        return visible_rows[visible_row] if 0 <= visible_row < len(visible_rows) else None

    def generate_test_unauthorized(self) -> None:
        alert = self.manager.create_test_unauthorized_alert()
        if alert:
            self.load_rows()
            self.alert_created.emit(alert)

    def generate_test_blacklist(self) -> None:
        alert = self.manager.create_test_blacklist_alert()
        if alert:
            self.load_rows()
            self.alert_created.emit(alert)

    def add_live_alert(self, alert: dict[str, str]) -> None:
        self.rows.append(alert)
        self.insert_alert(alert)
        self.alert_created.emit(alert)

    def build_alert_detail(self, alert: dict[str, str], forensic_result: dict | None = None) -> str:
        forensic_result = forensic_result or self.forensic.latest_for_ip(alert.get("dst_ip", "")) or {}
        abuse = forensic_result.get("abuse_contact") or NO_ABUSE_CONTACT
        parts = [
            "Informacion general",
            f"Fecha y hora: {alert.get('date', '')} {alert.get('time', '')}",
            f"Severidad: {alert.get('severity', '')}",
            f"Estado: {alert.get('status', '')}",
            f"Riesgo: {alert.get('risk_type', '')}",
            f"Mensaje: {alert.get('message', '')}",
            "",
            "Datos IP/MAC",
            f"IP origen: {alert.get('src_ip', '')}",
            f"MAC origen: {alert.get('src_mac', '')}",
            f"IP destino: {alert.get('dst_ip', '')}",
            "",
            "Informacion WHOIS/Abuse",
            f"ASN: {forensic_result.get('asn') or 'N/D'}",
            f"Pais: {forensic_result.get('country') or 'N/D'}",
            f"Proveedor: {forensic_result.get('provider') or 'N/D'}",
            f"Abuse contact: {abuse}",
            f"Resumen: {forensic_result.get('raw_summary') or 'Sin resultado forense registrado.'}",
            "",
            "Recomendacion operativa",
        ]
        if alert.get("severity", "").upper() == "EMERGENCY":
            parts.append("Bloquear IP temporalmente, revisar equipo origen y reportar al abuse contact si procede.")
        elif alert.get("risk_type", "").startswith("UNKNOWN"):
            parts.append("Verifique si el equipo pertenece a la organizacion antes de autorizarlo.")
        else:
            parts.append("Revise el evento, documente la decision y marque la alerta como revisada.")
        return "\n".join(parts)

    def refresh(self) -> None:
        self.load_rows()

    def update_cards(self) -> None:
        total = len(self.rows)
        critical = sum(1 for row in self.rows if row.get("severity", "").upper() == "CRITICAL")
        emergency = sum(1 for row in self.rows if row.get("severity", "").upper() == "EMERGENCY")
        last = self.rows[-1] if self.rows else {}
        self.total_card.value.setText(str(total))
        self.critical_card.value.setText(str(critical))
        self.emergency_card.value.setText(str(emergency))
        self.last_card.value.setText(last.get("risk_type", "-"))

    def severity_color(self, severity: str) -> str:
        normalized = severity.upper()
        if normalized == "EMERGENCY":
            return "#7a2f2f"
        if normalized == "CRITICAL":
            return "#6b3a2d"
        if normalized == "WARNING":
            return "#6b5524"
        return "#2d5b46"
