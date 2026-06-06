from pathlib import Path
from datetime import datetime

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.threat_intel import ThreatIntelService
from app.core.alert_manager import AlertManager
from app.core.forensic_lookup import ForensicLookupService
from app.utils.validators import is_valid_ip


class ThreatCard(QFrame):
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


class ThreatTab(QWidget):
    alert_created = pyqtSignal(dict)

    def __init__(self, base_path: Path):
        super().__init__()
        self.service = ThreatIntelService(base_path)
        self.alert_manager = AlertManager(base_path)
        self.forensic = ForensicLookupService(base_path)
        self.rows: list[dict] = []
        self.selected_ip = ""

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        title = QLabel("Threat Intelligence Local")
        title.setObjectName("SectionTitle")
        subtitle = QLabel("Gestion de IPs externas asociadas a riesgos de malware, botnet o actividad sospechosa")
        subtitle.setObjectName("Muted")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        cards = QGridLayout()
        self.total_card = ThreatCard("Total de IPs peligrosas", "0", "#d5a93b")
        self.botnet_card = ThreatCard("Riesgos tipo Botnet", "0", "#dc5b5b")
        self.malware_card = ThreatCard("Riesgos tipo Malware", "0", "#ff8f70")
        self.updated_card = ThreatCard("Ultima actualizacion", "-", "#aeb6c2")
        cards.addWidget(self.total_card, 0, 0)
        cards.addWidget(self.botnet_card, 0, 1)
        cards.addWidget(self.malware_card, 0, 2)
        cards.addWidget(self.updated_card, 0, 3)
        layout.addLayout(cards)

        content = QHBoxLayout()
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["IP", "Tipo de riesgo", "Severidad", "Fuente", "Descripcion"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        content.addWidget(self.table, 2)

        form_panel = QFrame()
        form_panel.setObjectName("Panel")
        form_layout = QVBoxLayout(form_panel)
        form_title = QLabel("Indicador local")
        form_title.setObjectName("SectionTitle")
        form_layout.addWidget(form_title)
        form = QFormLayout()
        self.ip_input = QLineEdit()
        self.risk_input = QLineEdit()
        self.severity_input = QComboBox()
        self.severity_input.addItems(["EMERGENCY", "CRITICAL", "WARNING", "INFO"])
        self.source_input = QLineEdit()
        self.description_input = QTextEdit()
        self.description_input.setFixedHeight(90)
        form.addRow("IP", self.ip_input)
        form.addRow("Tipo de riesgo", self.risk_input)
        form.addRow("Severidad", self.severity_input)
        form.addRow("Fuente", self.source_input)
        form.addRow("Descripcion", self.description_input)
        form_layout.addLayout(form)

        buttons = QGridLayout()
        self.add_button = QPushButton("Agregar IP")
        self.edit_button = QPushButton("Editar seleccionada")
        self.delete_button = QPushButton("Eliminar seleccionada")
        self.test_button = QPushButton("Probar IP")
        self.whois_button = QPushButton("Consultar WHOIS de IP seleccionada")
        self.alert_button = QPushButton("Generar alerta de prueba con esta IP")
        self.reload_button = QPushButton("Recargar blacklist")
        buttons.addWidget(self.add_button, 0, 0)
        buttons.addWidget(self.edit_button, 0, 1)
        buttons.addWidget(self.delete_button, 1, 0)
        buttons.addWidget(self.test_button, 1, 1)
        buttons.addWidget(self.whois_button, 2, 0, 1, 2)
        buttons.addWidget(self.alert_button, 3, 0, 1, 2)
        buttons.addWidget(self.reload_button, 4, 0, 1, 2)
        form_layout.addLayout(buttons)
        risk_note = QLabel("Riesgo: estas IPs se usan para correlacion local. Una coincidencia genera alerta EMERGENCY y consulta WHOIS/Abuse.")
        risk_note.setWordWrap(True)
        risk_note.setObjectName("Muted")
        self.whois_result = QTextEdit()
        self.whois_result.setReadOnly(True)
        self.whois_result.setFixedHeight(140)
        form_layout.addWidget(risk_note)
        form_layout.addWidget(QLabel("Resultado WHOIS"))
        form_layout.addWidget(self.whois_result)
        content.addWidget(form_panel, 1)
        layout.addLayout(content, 1)

        self.table.itemSelectionChanged.connect(self.load_selection)
        self.ip_input.textChanged.connect(self.validate_ip)
        self.add_button.clicked.connect(self.add_indicator)
        self.edit_button.clicked.connect(self.edit_indicator)
        self.delete_button.clicked.connect(self.delete_indicator)
        self.test_button.clicked.connect(self.test_lookup)
        self.whois_button.clicked.connect(self.lookup_selected_whois)
        self.alert_button.clicked.connect(self.generate_alert_for_selected)
        self.reload_button.clicked.connect(self.load_rows)
        self.load_rows()

    def load_rows(self) -> None:
        self.rows = self.service.indicators()
        self.table.setRowCount(len(self.rows))
        for row_index, row in enumerate(self.rows):
            values = [
                row.get("ip", ""),
                row.get("risk_type", ""),
                row.get("severity", ""),
                row.get("source", ""),
                row.get("description", ""),
            ]
            for column, value in enumerate(values):
                self.table.setItem(row_index, column, QTableWidgetItem(value))
        self.update_cards()

    def load_selection(self) -> None:
        selected = self.table.selectedItems()
        if not selected:
            return
        row = self.rows[selected[0].row()]
        self.selected_ip = row.get("ip", "")
        self.ip_input.setText(row.get("ip", ""))
        self.risk_input.setText(row.get("risk_type", ""))
        severity_index = self.severity_input.findText(row.get("severity", "").upper())
        self.severity_input.setCurrentIndex(severity_index if severity_index >= 0 else 0)
        self.source_input.setText(row.get("source", ""))
        self.description_input.setPlainText(row.get("description", ""))

    def add_indicator(self) -> None:
        ok, message = self.service.add_indicator(*self.form_values())
        self.show_result(ok, message)

    def edit_indicator(self) -> None:
        if not self.selected_ip:
            QMessageBox.information(self, "Threat Intelligence", "Seleccione una IP para editar.")
            return
        ok, message = self.service.update_indicator(self.selected_ip, *self.form_values())
        self.show_result(ok, message)

    def delete_indicator(self) -> None:
        if not self.selected_ip:
            QMessageBox.information(self, "Threat Intelligence", "Seleccione una IP para eliminar.")
            return
        ok, message = self.service.delete_indicator(self.selected_ip)
        self.show_result(ok, message)

    def test_lookup(self) -> None:
        default_ip = self.ip_input.text().strip()
        ip, accepted = QInputDialog.getText(self, "Consulta local", "IP a consultar:", text=default_ip)
        if not accepted:
            return
        result = self.service.lookup_local(ip)
        if result.get("found"):
            indicator = result["indicator"]
            QMessageBox.warning(
                self,
                "Indicador encontrado",
                f"{indicator['ip']} - {indicator['risk_type']} ({indicator['severity']})\n{indicator.get('description', '')}",
            )
        else:
            QMessageBox.information(self, "Consulta local", result.get("message", "Sin coincidencias."))

    def lookup_selected_whois(self) -> None:
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.information(self, "WHOIS", "Seleccione o escriba una IP.")
            return
        result = self.forensic.lookup_ip(ip)
        self.whois_result.setPlainText(self.forensic.build_forensic_summary(result))
        QMessageBox.information(self, "WHOIS", "Consulta WHOIS guardada en forensic_log.csv.")

    def generate_alert_for_selected(self) -> None:
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.information(self, "Threat Intelligence", "Seleccione una IP para generar alerta.")
            return
        result = self.service.lookup_local(ip)
        if result.get("found"):
            indicator = result["indicator"]
        else:
            indicator = {
                "ip": ip,
                "risk_type": self.risk_input.text().strip() or "IP peligrosa",
                "severity": self.severity_input.currentText(),
                "source": self.source_input.text().strip() or "Demo local",
                "description": self.description_input.toPlainText().strip() or "Indicador usado para demostracion.",
            }
        alert = self.alert_manager.create_blacklist_alert("192.168.1.25", "AA:BB:CC:DD:EE:01", ip, indicator, force=True)
        if alert:
            self.alert_created.emit(alert)
            QMessageBox.warning(self, "Alerta generada", "Alerta EMERGENCY guardada en alerts_log.csv y forensic_log.csv.")

    def form_values(self) -> tuple[str, str, str, str, str]:
        return (
            self.ip_input.text().strip(),
            self.risk_input.text().strip(),
            self.severity_input.currentText(),
            self.source_input.text().strip(),
            self.description_input.toPlainText().strip(),
        )

    def show_result(self, ok: bool, message: str) -> None:
        if ok:
            self.clear_form()
            self.load_rows()
            QMessageBox.information(self, "Threat Intelligence", message)
        else:
            QMessageBox.warning(self, "Threat Intelligence", message)

    def clear_form(self) -> None:
        self.selected_ip = ""
        self.ip_input.clear()
        self.risk_input.clear()
        self.severity_input.setCurrentIndex(0)
        self.source_input.clear()
        self.description_input.clear()

    def validate_ip(self) -> None:
        invalid = bool(self.ip_input.text().strip()) and not is_valid_ip(self.ip_input.text().strip())
        self.ip_input.setProperty("invalid", invalid)
        self.ip_input.style().unpolish(self.ip_input)
        self.ip_input.style().polish(self.ip_input)

    def update_cards(self) -> None:
        botnets = sum(1 for row in self.rows if "botnet" in row.get("risk_type", "").lower())
        malware = sum(1 for row in self.rows if "malware" in row.get("risk_type", "").lower())
        self.total_card.value.setText(str(len(self.rows)))
        self.botnet_card.value.setText(str(botnets))
        self.malware_card.value.setText(str(malware))
        self.updated_card.value.setText(datetime.now().strftime("%H:%M:%S"))

    def refresh(self) -> None:
        self.load_rows()
