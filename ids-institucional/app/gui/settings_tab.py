from pathlib import Path

try:
    from dotenv import dotenv_values, set_key
except ImportError:
    def dotenv_values(path):
        values = {}
        try:
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip().strip('"').strip("'")
        except OSError:
            pass
        return values

    def set_key(path, key, value):
        target = Path(path)
        lines = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
        updated = False
        for index, line in enumerate(lines):
            if line.startswith(f"{key}="):
                lines[index] = f"{key}={value}"
                updated = True
                break
        if not updated:
            lines.append(f"{key}={value}")
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.core.alert_manager import AlertManager
from app.utils.config_loader import read_json, write_json
from app.utils.network_utils import list_network_interfaces


class SettingsTab(QWidget):
    def __init__(self, base_path: Path):
        super().__init__()
        self.base_path = base_path
        self.path = base_path / "data" / "settings.json"
        self.env_path = base_path / ".env"
        self.env_example_path = base_path / ".env.example"
        self.alert_manager = AlertManager(base_path)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel("Configuracion Operativa del IDS")
        title.setObjectName("SectionTitle")
        subtitle = QLabel(
            "Centralice aqui las opciones de monitoreo, correo y variables de entorno. Los datos sensibles se guardan en .env, "
            "mientras que settings.json conserva preferencias no sensibles como interfaz, cooldown y estado SMTP."
        )
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        warning = QLabel("Nunca escriba contrasenas directamente en el codigo fuente. Use .env y mantengalo fuera de repositorios.")
        warning.setWordWrap(True)
        warning.setStyleSheet("background: #4a3e23; border-radius: 8px; padding: 10px; font-weight: 700;")
        layout.addWidget(warning)

        top_grid = QGridLayout()
        top_grid.addWidget(self._build_admin_panel(), 0, 0)
        top_grid.addWidget(self._build_capture_panel(), 0, 1)
        layout.addLayout(top_grid)

        layout.addWidget(self._build_smtp_panel())
        layout.addWidget(self._build_env_panel())

        buttons = QGridLayout()
        self.save_button = QPushButton("Guardar configuracion")
        self.test_mail_button = QPushButton("Probar correo")
        self.reload_button = QPushButton("Recargar configuracion")
        self.create_env_button = QPushButton("Crear .env desde plantilla")
        buttons.addWidget(self.save_button, 0, 0)
        buttons.addWidget(self.test_mail_button, 0, 1)
        buttons.addWidget(self.reload_button, 0, 2)
        buttons.addWidget(self.create_env_button, 0, 3)
        layout.addLayout(buttons)
        layout.addStretch()

        self.save_button.clicked.connect(self.save)
        self.test_mail_button.clicked.connect(self.test_email)
        self.reload_button.clicked.connect(self.reload)
        self.create_env_button.clicked.connect(self.create_env_from_template)
        self.reload()

    def _build_admin_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("Panel")
        form = QFormLayout(panel)
        title = QLabel("Correo del administrador")
        title.setObjectName("SectionTitle")
        hint = QLabel("Destino principal de alertas. Puede venir de ADMIN_EMAIL en .env o guardarse como referencia no sensible en JSON.")
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        self.admin_email = QLineEdit()
        self.admin_email.setPlaceholderText("admin@institucion.mx")
        form.addRow(title)
        form.addRow(hint)
        form.addRow("ADMIN_EMAIL", self.admin_email)
        return panel

    def _build_capture_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("Panel")
        form = QFormLayout(panel)
        title = QLabel("Captura de red")
        title.setObjectName("SectionTitle")
        hint = QLabel("Seleccione la interfaz que transporta el trafico. Para captura real ejecute: sudo venv/bin/python main.py")
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        self.capture_interface = QComboBox()
        self.cooldown = QSpinBox()
        self.cooldown.setRange(0, 86400)
        self.cooldown.setSuffix(" segundos")
        form.addRow(title)
        form.addRow(hint)
        form.addRow("Interfaz activa", self.capture_interface)
        form.addRow("Cooldown de alertas", self.cooldown)
        return panel

    def _build_smtp_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("Panel")
        form = QFormLayout(panel)
        title = QLabel("Servidor SMTP")
        title.setObjectName("SectionTitle")
        self.smtp_status_label = QLabel()
        self.smtp_status_label.setWordWrap(True)
        self.smtp_enabled = QCheckBox("Enviar correos reales si .env esta completo")
        self.smtp_starttls = QCheckBox("Usar STARTTLS")
        self.smtp_host = QLineEdit()
        self.smtp_port = QSpinBox()
        self.smtp_port.setRange(1, 65535)
        self.smtp_user = QLineEdit()
        self.smtp_password = QLineEdit()
        self.smtp_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.smtp_from = QLineEdit()
        self.smtp_host.setPlaceholderText("smtp.gmail.com")
        self.smtp_user.setPlaceholderText("correo_admin@example.com")
        self.smtp_password.setPlaceholderText("Contrasena de aplicacion")
        self.smtp_from.setPlaceholderText("ids@example.com")
        form.addRow(title)
        form.addRow("Estado", self.smtp_status_label)
        form.addRow("SMTP_ENABLED", self.smtp_enabled)
        form.addRow("SMTP_STARTTLS", self.smtp_starttls)
        form.addRow("SMTP_HOST", self.smtp_host)
        form.addRow("SMTP_PORT", self.smtp_port)
        form.addRow("SMTP_USER", self.smtp_user)
        form.addRow("SMTP_PASSWORD", self.smtp_password)
        form.addRow("SMTP_FROM", self.smtp_from)
        return panel

    def _build_env_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("Panel")
        layout = QVBoxLayout(panel)
        title = QLabel("Variables de entorno y ejecucion")
        title.setObjectName("SectionTitle")
        self.env_status = QLabel()
        self.env_status.setWordWrap(True)
        command = QLabel("Comando recomendado para monitoreo real: sudo venv/bin/python main.py")
        command.setObjectName("Muted")
        command.setWordWrap(True)
        note = QLabel(
            "Si solo desea revisar la interfaz o usar modo demo, python main.py es suficiente. Para captura real, Debian requiere permisos de socket crudo."
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(self.env_status)
        layout.addWidget(command)
        layout.addWidget(note)
        return panel

    def reload(self) -> None:
        self.settings = read_json(self.path, {})
        self.env_values = dotenv_values(self.env_path) if self.env_path.exists() else {}

        self.admin_email.setText(str(self.env_values.get("ADMIN_EMAIL") or self.settings.get("admin_email", "")))
        self.smtp_enabled.setChecked(self._bool_value(self.env_values.get("SMTP_ENABLED"), bool(self.settings.get("smtp_enabled", False))))
        self.smtp_starttls.setChecked(self._bool_value(self.env_values.get("SMTP_STARTTLS"), True))
        self.smtp_host.setText(str(self.env_values.get("SMTP_HOST") or "smtp.gmail.com"))
        self.smtp_port.setValue(self._int_value(self.env_values.get("SMTP_PORT"), 587))
        self.smtp_user.setText(str(self.env_values.get("SMTP_USER") or ""))
        self.smtp_password.setText(str(self.env_values.get("SMTP_PASSWORD") or ""))
        self.smtp_from.setText(str(self.env_values.get("SMTP_FROM") or ""))
        self.cooldown.setValue(int(self.settings.get("alert_cooldown_seconds", self._int_value(self.env_values.get("ALERT_COOLDOWN_SECONDS"), 300))))

        self.capture_interface.clear()
        interfaces = list_network_interfaces()
        configured = self.settings.get("capture_interface", "")
        if configured and configured not in interfaces:
            interfaces.insert(0, configured)
        self.capture_interface.addItems(interfaces or ["eth0"])
        if configured:
            index = self.capture_interface.findText(configured)
            if index >= 0:
                self.capture_interface.setCurrentIndex(index)
        self.update_smtp_status()

    def save(self, show_popup: bool = True) -> None:
        self.env_path.touch(exist_ok=True)
        env_updates = {
            "SMTP_ENABLED": "true" if self.smtp_enabled.isChecked() else "false",
            "SMTP_HOST": self.smtp_host.text().strip(),
            "SMTP_PORT": str(self.smtp_port.value()),
            "SMTP_STARTTLS": "true" if self.smtp_starttls.isChecked() else "false",
            "SMTP_USER": self.smtp_user.text().strip(),
            "SMTP_PASSWORD": self.smtp_password.text(),
            "SMTP_FROM": self.smtp_from.text().strip(),
            "ADMIN_EMAIL": self.admin_email.text().strip(),
            "ALERT_COOLDOWN_SECONDS": str(self.cooldown.value()),
        }
        for key, value in env_updates.items():
            set_key(str(self.env_path), key, value)

        self.settings["admin_email"] = self.admin_email.text().strip()
        self.settings["smtp_enabled"] = self.smtp_enabled.isChecked()
        self.settings["alert_cooldown_seconds"] = self.cooldown.value()
        self.settings["capture_interface"] = self.capture_interface.currentText().strip() or "eth0"
        write_json(self.path, self.settings)
        self.alert_manager = AlertManager(self.base_path)
        self.update_smtp_status()
        if show_popup:
            QMessageBox.information(self, "Configuracion", "Configuracion guardada. Los secretos se escribieron en .env y las preferencias en settings.json.")

    def create_env_from_template(self) -> None:
        if self.env_path.exists():
            QMessageBox.information(self, "Variables de entorno", ".env ya existe. No se sobrescribio.")
            return
        if self.env_example_path.exists():
            self.env_path.write_text(self.env_example_path.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            self.env_path.write_text("SMTP_ENABLED=false\nALERT_COOLDOWN_SECONDS=300\n", encoding="utf-8")
        self.reload()
        QMessageBox.information(self, "Variables de entorno", ".env creado desde plantilla. Complete los valores reales antes de habilitar SMTP.")

    def test_email(self) -> None:
        self.save(show_popup=False)
        result = self.alert_manager.test_email()
        message = f"Estado: {result.get('status')}\nDetalle: {result.get('message')}"
        if result.get("status") == "Enviado":
            QMessageBox.information(self, "Prueba SMTP", message)
        elif result.get("status") == "Simulado":
            QMessageBox.information(self, "Prueba SMTP simulada", message)
        else:
            QMessageBox.warning(self, "Prueba SMTP", message)

    def update_smtp_status(self) -> None:
        status = self.alert_manager.smtp_status()
        env_exists = self.env_path.exists()
        if status["enabled"]:
            label = "Habilitado"
            color = "#244f3f"
        else:
            label = "Simulado / Deshabilitado"
            color = "#4a3e23"
        self.smtp_status_label.setText(
            f"{label} | Host: {status.get('host') or self.smtp_host.text() or 'sin configurar'} | "
            f"Usuario: {'configurado' if self.smtp_user.text().strip() else 'sin configurar'} | "
            f"Destino: {self.admin_email.text().strip() or 'sin configurar'}"
        )
        self.smtp_status_label.setStyleSheet(f"background: {color}; border-radius: 6px; padding: 8px; font-weight: 700;")
        self.env_status.setText(
            f"Archivo .env: {'existe' if env_exists else 'no existe'} | Plantilla .env.example: "
            f"{'disponible' if self.env_example_path.exists() else 'no encontrada'}"
        )

    def _bool_value(self, value, default: bool) -> bool:
        if value is None:
            return default
        return str(value).strip().lower() in ["1", "true", "yes", "on", "si"]

    def _int_value(self, value, default: int) -> int:
        try:
            return int(str(value))
        except (TypeError, ValueError):
            return default

    def refresh(self) -> None:
        self.reload()
