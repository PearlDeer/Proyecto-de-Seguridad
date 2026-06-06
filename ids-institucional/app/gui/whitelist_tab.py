from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.whitelist_manager import WhitelistManager
from app.utils.validators import is_valid_ip, is_valid_mac


class SummaryCard(QFrame):
    def __init__(self, title: str):
        super().__init__()
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("Muted")
        self.value_label = QLabel("0")
        self.value_label.setStyleSheet("font-size: 24px; font-weight: 800; color: #e6e9ef;")
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)

    def set_value(self, value: str) -> None:
        self.value_label.setText(value)


class WhitelistTab(QWidget):
    def __init__(self, base_path: Path):
        super().__init__()
        self.manager = WhitelistManager(base_path)
        self.selected_id: int | None = None

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        header = QVBoxLayout()
        title = QLabel("Lista Blanca de Equipos Autorizados")
        title.setObjectName("SectionTitle")
        subtitle = QLabel(
            "Administre los equipos permitidos por direccion IP y MAC. Esta lista se usa para distinguir activos institucionales "
            "de dispositivos desconocidos cuando el sniffer detecta trafico en la red."
        )
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        header.addWidget(title)
        header.addWidget(subtitle)
        layout.addLayout(header)

        cards = QGridLayout()
        self.total_card = SummaryCard("Total de equipos autorizados")
        self.ip_card = SummaryCard("IPs registradas")
        self.mac_card = SummaryCard("MACs registradas")
        self.updated_card = SummaryCard("Ultima actualizacion")
        cards.addWidget(self.total_card, 0, 0)
        cards.addWidget(self.ip_card, 0, 1)
        cards.addWidget(self.mac_card, 0, 2)
        cards.addWidget(self.updated_card, 0, 3)
        layout.addLayout(cards)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        table_panel = QFrame()
        table_panel.setObjectName("Panel")
        table_layout = QVBoxLayout(table_panel)
        table_layout.setContentsMargins(10, 10, 10, 10)
        table_title = QLabel("Activos registrados")
        table_title.setObjectName("SectionTitle")
        table_hint = QLabel("Seleccione una fila para revisar o editar sus datos. La tabla tiene prioridad para facilitar la lectura durante la presentacion.")
        table_hint.setObjectName("Muted")
        table_hint.setWordWrap(True)
        table_layout.addWidget(table_title)
        table_layout.addWidget(table_hint)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["ID", "Equipo", "IP", "MAC", "Descripcion", "Creado"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setMinimumHeight(420)
        table_layout.addWidget(self.table)

        form_panel = QFrame()
        form_panel.setObjectName("Panel")
        form_panel.setMinimumWidth(360)
        form_panel.setMaximumWidth(440)
        form_layout = QVBoxLayout(form_panel)
        form_layout.setContentsMargins(12, 12, 12, 12)
        form_layout.setSpacing(10)
        form_title = QLabel("Detalle del equipo")
        form_title.setObjectName("SectionTitle")
        form_hint = QLabel("Registre solo equipos autorizados por la organizacion. Una IP o MAC mal escrita puede generar alertas falsas.")
        form_hint.setObjectName("Muted")
        form_hint.setWordWrap(True)
        form_layout.addWidget(form_title)
        form_layout.addWidget(form_hint)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        self.name_input = QLineEdit()
        self.ip_input = QLineEdit()
        self.mac_input = QLineEdit()
        self.description_input = QTextEdit()
        self.description_input.setFixedHeight(72)
        self.name_input.setPlaceholderText("Ej. Equipo Administracion")
        self.ip_input.setPlaceholderText("Ej. 192.168.1.25")
        self.mac_input.setPlaceholderText("Ej. AA:BB:CC:DD:EE:01")
        self.description_input.setPlaceholderText("Area, responsable o proposito del equipo")
        form.addRow("Nombre del equipo", self.name_input)
        form.addRow("Direccion IP", self.ip_input)
        form.addRow("Direccion MAC", self.mac_input)
        form.addRow("Descripcion", self.description_input)
        form_layout.addLayout(form)

        self.status_label = QLabel("Seleccione un equipo o registre uno nuevo.")
        self.status_label.setWordWrap(True)
        self.status_label.setObjectName("Muted")
        form_layout.addWidget(self.status_label)

        self.add_button = QPushButton("Agregar equipo")
        self.edit_button = QPushButton("Editar seleccionado")
        self.delete_button = QPushButton("Eliminar seleccionado")
        self.clear_button = QPushButton("Limpiar formulario")
        self.reload_button = QPushButton("Recargar lista")
        action_grid = QGridLayout()
        action_grid.addWidget(self.add_button, 0, 0, 1, 2)
        action_grid.addWidget(self.edit_button, 1, 0)
        action_grid.addWidget(self.delete_button, 1, 1)
        action_grid.addWidget(self.clear_button, 2, 0)
        action_grid.addWidget(self.reload_button, 2, 1)
        form_layout.addLayout(action_grid)
        form_layout.addStretch()

        splitter.addWidget(table_panel)
        splitter.addWidget(form_panel)
        splitter.setSizes([980, 360])
        layout.addWidget(splitter, 1)

        self.add_button.clicked.connect(self.add_device)
        self.edit_button.clicked.connect(self.edit_selected)
        self.delete_button.clicked.connect(self.delete_selected)
        self.clear_button.clicked.connect(self.clear_form)
        self.reload_button.clicked.connect(self.reload_devices)
        self.table.itemSelectionChanged.connect(self.populate_from_selection)
        self.load_devices()

    def validate_form(self) -> bool:
        has_name = bool(self.name_input.text().strip())
        valid_ip = is_valid_ip(self.ip_input.text())
        valid_mac = is_valid_mac(self.mac_input.text())
        self.name_input.setProperty("invalid", not has_name)
        self.ip_input.setProperty("invalid", not valid_ip)
        self.mac_input.setProperty("invalid", not valid_mac)
        for widget in [self.name_input, self.ip_input, self.mac_input]:
            widget.style().unpolish(widget)
            widget.style().polish(widget)

        if not has_name:
            self.show_message("Falta el nombre del equipo.", success=False)
            return False
        if not valid_ip:
            self.show_message("La IP es invalida.", success=False)
            return False
        if not valid_mac:
            self.show_message("La MAC es invalida.", success=False)
            return False
        return True

    def add_device(self) -> None:
        if not self.validate_form():
            return
        success, message = self.manager.add_device(self.name_input.text(), self.ip_input.text(), self.mac_input.text(), self.description_input.toPlainText())
        self.handle_result(success, message)
        if success:
            self.clear_form()
            self.load_devices()

    def edit_selected(self) -> None:
        if self.selected_id is None or not self.validate_form():
            if self.selected_id is None:
                self.show_message("Seleccione un equipo para editar.", success=False)
            return
        success, message = self.manager.update_device(self.selected_id, self.name_input.text(), self.ip_input.text(), self.mac_input.text(), self.description_input.toPlainText())
        self.handle_result(success, message)
        if success:
            self.load_devices()

    def delete_selected(self) -> None:
        if self.selected_id is None:
            self.show_message("Seleccione un equipo para eliminar.", success=False)
            return
        success, message = self.manager.delete_device(self.selected_id)
        self.handle_result(success, message)
        if success:
            self.clear_form()
            self.load_devices()

    def populate_from_selection(self) -> None:
        items = self.table.selectedItems()
        if not items:
            return
        row = items[0].row()
        self.selected_id = int(self.table.item(row, 0).text())
        self.name_input.setText(self.table.item(row, 1).text())
        self.ip_input.setText(self.table.item(row, 2).text())
        self.mac_input.setText(self.table.item(row, 3).text())
        self.description_input.setPlainText(self.table.item(row, 4).text())
        self.show_message(f"Equipo seleccionado: {self.name_input.text()}", success=True, popup=False)

    def clear_form(self) -> None:
        self.selected_id = None
        for widget in [self.name_input, self.ip_input, self.mac_input, self.description_input]:
            widget.clear()
            widget.setProperty("invalid", False)
            widget.style().unpolish(widget)
            widget.style().polish(widget)
        self.table.clearSelection()
        self.show_message("Formulario limpio.", success=True, popup=False)

    def reload_devices(self) -> None:
        self.clear_form()
        self.load_devices()
        self.show_message("Lista blanca recargada desde whitelist.json.", success=True)

    def load_devices(self) -> None:
        devices = self.manager.all_devices()
        self.table.setRowCount(len(devices))
        for row, device in enumerate(devices):
            values = [device.get("id", ""), device.get("device_name", ""), device.get("ip", ""), device.get("mac", ""), device.get("description", ""), device.get("created_at", "")]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(str(value)))
        self.table.setColumnWidth(0, 54)
        self.table.setColumnWidth(1, 210)
        self.table.setColumnWidth(2, 150)
        self.table.setColumnWidth(3, 190)
        self.table.setColumnWidth(4, 300)
        self.update_cards(devices)

    def update_cards(self, devices: list[dict]) -> None:
        ips = {device.get("ip", "") for device in devices if device.get("ip")}
        macs = {device.get("mac", "") for device in devices if device.get("mac")}
        last_update = self.manager.log_manager.last_system_event("WHITELIST")
        self.total_card.set_value(str(len(devices)))
        self.ip_card.set_value(str(len(ips)))
        self.mac_card.set_value(str(len(macs)))
        self.updated_card.set_value(f"{last_update.get('date', '')} {last_update.get('time', '')}".strip() if last_update else "Sin eventos")

    def handle_result(self, success: bool, message: str) -> None:
        self.show_message(message, success=success)

    def show_message(self, message: str, success: bool, popup: bool = True) -> None:
        color = "#3fb27f" if success else "#dc5b5b"
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {color}; font-weight: 700;")
        if popup:
            if success:
                QMessageBox.information(self, "Lista Blanca", message)
            else:
                QMessageBox.warning(self, "Lista Blanca", message)

    def refresh(self) -> None:
        self.load_devices()
