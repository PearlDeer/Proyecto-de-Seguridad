from pathlib import Path

from PyQt6.QtWidgets import QFormLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QVBoxLayout, QWidget

from app.utils.config_loader import read_json, write_json


class SettingsTab(QWidget):
    def __init__(self, base_path: Path):
        super().__init__()
        self.path = base_path / "data" / "settings.json"
        self.settings = read_json(self.path, {})
        layout = QVBoxLayout(self)
        notice = QLabel("Las credenciales SMTP y API Keys deben almacenarse en .env. Este panel solo guarda configuracion no sensible.")
        notice.setWordWrap(True)
        notice.setObjectName("Muted")
        layout.addWidget(notice)
        form = QFormLayout()
        self.admin_email = QLineEdit(self.settings.get("admin_email", ""))
        self.smtp_server = QLineEdit("smtp.example.org")
        self.interface = QLineEdit(self.settings.get("capture_interface", "eth0"))
        self.api_key = QLineEdit("********")
        self.api_key.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Correo administrador", self.admin_email)
        form.addRow("Servidor SMTP", self.smtp_server)
        form.addRow("Interfaz de captura", self.interface)
        form.addRow("API Key", self.api_key)
        layout.addLayout(form)
        self.save_button = QPushButton("Guardar configuracion")
        self.test_button = QPushButton("Probar configuracion")
        layout.addWidget(self.save_button)
        layout.addWidget(self.test_button)
        layout.addStretch()
        self.save_button.clicked.connect(self.save)
        self.test_button.clicked.connect(self.test)

    def save(self) -> None:
        self.settings["admin_email"] = self.admin_email.text().strip()
        self.settings["capture_interface"] = self.interface.text().strip() or "eth0"
        write_json(self.path, self.settings)
        QMessageBox.information(self, "Configuracion", "Configuracion no sensible guardada en JSON.")

    def test(self) -> None:
        QMessageBox.information(self, "Prueba simulada", "Validacion visual completada. La conexion SMTP/API real se habilitara en una fase posterior.")
