from pathlib import Path

from PyQt6.QtWidgets import QFormLayout, QHBoxLayout, QHeaderView, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from app.core.whitelist_manager import WhitelistManager
from app.utils.validators import is_valid_ip, is_valid_mac


class WhitelistTab(QWidget):
    def __init__(self, base_path: Path):
        super().__init__()
        self.manager = WhitelistManager(base_path)
        self.selected_id: int | None = None

        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.name_input = QLineEdit()
        self.ip_input = QLineEdit()
        self.mac_input = QLineEdit()
        self.description_input = QLineEdit()
        form.addRow("Nombre del equipo", self.name_input)
        form.addRow("IP", self.ip_input)
        form.addRow("MAC", self.mac_input)
        form.addRow("Descripcion", self.description_input)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.add_button = QPushButton("Agregar")
        self.edit_button = QPushButton("Editar")
        self.delete_button = QPushButton("Eliminar")
        self.reload_button = QPushButton("Recargar")
        for button in [self.add_button, self.edit_button, self.delete_button, self.reload_button]:
            buttons.addWidget(button)
        buttons.addStretch()
        layout.addLayout(buttons)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["ID", "Equipo", "IP", "MAC", "Descripcion", "Creado"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

        self.add_button.clicked.connect(self.add_device)
        self.edit_button.clicked.connect(self.edit_selected)
        self.delete_button.clicked.connect(self.delete_selected)
        self.reload_button.clicked.connect(self.load_devices)
        self.table.itemSelectionChanged.connect(self.populate_from_selection)
        self.load_devices()

    def validate_form(self) -> bool:
        valid_ip = is_valid_ip(self.ip_input.text())
        valid_mac = is_valid_mac(self.mac_input.text())
        self.ip_input.setProperty("invalid", not valid_ip)
        self.mac_input.setProperty("invalid", not valid_mac)
        self.ip_input.style().unpolish(self.ip_input)
        self.ip_input.style().polish(self.ip_input)
        self.mac_input.style().unpolish(self.mac_input)
        self.mac_input.style().polish(self.mac_input)
        return bool(self.name_input.text().strip() and valid_ip and valid_mac)

    def add_device(self) -> None:
        if not self.validate_form():
            return
        self.manager.add_device(self.name_input.text(), self.ip_input.text(), self.mac_input.text(), self.description_input.text())
        self.clear_form()
        self.load_devices()

    def edit_selected(self) -> None:
        if self.selected_id is None or not self.validate_form():
            return
        devices = self.manager.all_devices()
        for device in devices:
            if int(device.get("id", 0)) == self.selected_id:
                device.update({
                    "device_name": self.name_input.text().strip(),
                    "ip": self.ip_input.text().strip(),
                    "mac": self.mac_input.text().strip().upper(),
                    "description": self.description_input.text().strip(),
                })
        from app.utils.config_loader import write_json

        write_json(self.manager.path, devices)
        self.load_devices()

    def delete_selected(self) -> None:
        if self.selected_id is not None:
            self.manager.delete_device(self.selected_id)
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
        self.description_input.setText(self.table.item(row, 4).text())

    def clear_form(self) -> None:
        self.selected_id = None
        for widget in [self.name_input, self.ip_input, self.mac_input, self.description_input]:
            widget.clear()

    def load_devices(self) -> None:
        devices = self.manager.all_devices()
        self.table.setRowCount(len(devices))
        for row, device in enumerate(devices):
            values = [device.get("id", ""), device.get("device_name", ""), device.get("ip", ""), device.get("mac", ""), device.get("description", ""), device.get("created_at", "")]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(str(value)))
