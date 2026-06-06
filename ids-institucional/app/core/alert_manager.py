from datetime import datetime
from email.message import EmailMessage
import os
from pathlib import Path
import smtplib

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs) -> bool:
        return False

from app.core.log_manager import LogManager
from app.core.forensic_lookup import ForensicLookupService
from app.utils.config_loader import ADMIN_EMAIL_DEFAULT, read_json


SEVERITIES = ["INFO", "WARNING", "CRITICAL", "EMERGENCY"]


class AlertManager:
    _last_sent_by_key: dict[str, datetime] = {}

    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.log_manager = LogManager(base_path)
        self.forensic_lookup = ForensicLookupService(base_path)
        load_dotenv(base_path / ".env")

    def alerts(self) -> list[dict[str, str]]:
        return self.log_manager.alert_rows()

    def mark_reviewed(self, alert: dict[str, str]) -> None:
        self.log_manager.mark_alert_reviewed(alert)

    def create_unauthorized_device_alert(
        self,
        authorization: dict,
        src_ip: str,
        src_mac: str,
        dst_ip: str = "",
        force: bool = False,
    ) -> dict[str, str] | None:
        reason = authorization.get("reason", "UNKNOWN_DEVICE")
        messages = {
            "UNKNOWN_DEVICE": "Equipo no autorizado detectado en la red",
            "UNKNOWN_IP": "La MAC existe en whitelist pero esta usando una IP no registrada",
            "UNKNOWN_MAC": "La IP existe en whitelist pero la MAC no coincide",
        }
        severity = "CRITICAL" if reason in ["UNKNOWN_DEVICE", "UNKNOWN_MAC"] else "WARNING"
        alert = self._build_alert(
            severity=severity,
            src_ip=src_ip,
            src_mac=src_mac,
            dst_ip=dst_ip,
            risk_type=reason,
            message=messages.get(reason, "Equipo no autorizado detectado en la red"),
        )
        return self.register_alert(
            alert,
            subject="[IDS] Alerta de Equipo No Autorizado",
            body=self._unauthorized_body(alert),
            cooldown_key=f"WHITELIST:{reason}:{src_ip}:{src_mac}",
            force=force,
        )

    def create_blacklist_alert(self, src_ip: str, src_mac: str, dst_ip: str, indicator: dict, force: bool = False) -> dict[str, str] | None:
        risk_type = indicator.get("risk_type", "IP peligrosa")
        forensic_result = self.forensic_lookup.lookup_ip(dst_ip)
        alert = self._build_alert(
            severity="EMERGENCY",
            src_ip=src_ip,
            src_mac=src_mac,
            dst_ip=dst_ip,
            risk_type=risk_type,
            message=(
                f"IP peligrosa detectada: {dst_ip} | "
                f"Severidad feed: {indicator.get('severity', 'N/D')} | "
                f"Fuente: {indicator.get('source', 'N/D')} | "
                f"Descripcion: {indicator.get('description', 'N/D')}"
            ),
        )
        return self.register_alert(
            alert,
            subject="[IDS] Alerta de Emergencia - IP Peligrosa Detectada",
            body=self._blacklist_body(alert, indicator, forensic_result),
            cooldown_key=f"BLACKLIST:{src_ip}:{dst_ip}:{risk_type}",
            force=force,
        )

    def create_test_unauthorized_alert(self) -> dict[str, str] | None:
        return self.create_unauthorized_device_alert(
            {"authorized": False, "reason": "UNKNOWN_DEVICE", "device": None},
            "192.168.1.200",
            "DE:AD:BE:EF:00:02",
            "8.8.8.8",
            force=True,
        )

    def create_test_blacklist_alert(self) -> dict[str, str] | None:
        indicator = {
            "ip": "185.220.101.45",
            "risk_type": "Botnet",
            "severity": "EMERGENCY",
            "source": "Local Threat Feed",
            "description": "IP asociada a actividad maliciosa o infraestructura sospechosa",
        }
        return self.create_blacklist_alert("192.168.1.25", "AA:BB:CC:DD:EE:01", indicator["ip"], indicator, force=True)

    def test_email(self) -> dict[str, str]:
        alert = self._build_alert(
            severity="INFO",
            src_ip="127.0.0.1",
            src_mac="N/D",
            dst_ip="N/D",
            risk_type="SMTP_TEST",
            message="Prueba de correo del IDS Institucional",
        )
        return self._send_email("[IDS] Prueba de Correo SMTP", self._generic_body(alert), "SMTP_TEST", force=True)

    def register_alert(
        self,
        alert: dict[str, str],
        subject: str,
        body: str,
        cooldown_key: str,
        force: bool = False,
    ) -> dict[str, str] | None:
        if not force and self._is_in_cooldown(cooldown_key):
            return None

        mail_result = self._send_email(subject, body, cooldown_key, force=force)
        status_suffix = mail_result.get("status", "Simulado")
        alert["status"] = f"Nueva | Correo: {status_suffix}"
        self.log_manager.log_alert(alert)
        self._touch_cooldown(cooldown_key)
        return alert

    def smtp_status(self) -> dict[str, str | bool | int]:
        settings = read_json(self.base_path / "data" / "settings.json", {})
        env_enabled = self._env_bool("SMTP_ENABLED", False)
        setting_enabled = bool(settings.get("smtp_enabled", env_enabled))
        return {
            "enabled": setting_enabled,
            "env_enabled": env_enabled,
            "host": os.getenv("SMTP_HOST", ""),
            "port": self._env_int("SMTP_PORT", 587),
            "user_configured": bool(os.getenv("SMTP_USER", "")),
            "admin_email": os.getenv("ADMIN_EMAIL", settings.get("admin_email", ADMIN_EMAIL_DEFAULT)),
            "cooldown": self.cooldown_seconds(),
        }

    def cooldown_seconds(self) -> int:
        settings = read_json(self.base_path / "data" / "settings.json", {})
        return int(settings.get("alert_cooldown_seconds") or self._env_int("ALERT_COOLDOWN_SECONDS", 300))

    def normalize_severity(self, severity: str) -> str:
        value = str(severity or "INFO").strip().upper()
        aliases = {"ALTA": "CRITICAL", "CRITICA": "CRITICAL", "MEDIA": "WARNING", "BAJA": "INFO"}
        return aliases.get(value, value if value in SEVERITIES else "INFO")

    def _build_alert(self, severity: str, src_ip: str, src_mac: str, dst_ip: str, risk_type: str, message: str) -> dict[str, str]:
        now = datetime.now()
        return {
            "date": now.strftime("%Y-%m-%d"),
            "time": now.strftime("%H:%M:%S"),
            "severity": self.normalize_severity(severity),
            "src_ip": src_ip,
            "src_mac": src_mac,
            "dst_ip": dst_ip,
            "risk_type": risk_type,
            "message": message,
            "status": "Nueva",
        }

    def _send_email(self, subject: str, body: str, cooldown_key: str, force: bool = False) -> dict[str, str]:
        if not force and self._is_in_cooldown(f"MAIL:{cooldown_key}"):
            return {"status": "Cooldown", "message": "Correo omitido por cooldown"}

        status = self.smtp_status()
        if not status["enabled"]:
            self._touch_cooldown(f"MAIL:{cooldown_key}")
            return {"status": "Simulado", "message": "SMTP deshabilitado"}

        host = str(status["host"])
        port = int(status["port"])
        user = os.getenv("SMTP_USER", "")
        password = os.getenv("SMTP_PASSWORD", "")
        sender = os.getenv("SMTP_FROM", user)
        recipient = str(status["admin_email"])
        starttls = self._env_bool("SMTP_STARTTLS", True)

        if not host or not sender or not recipient:
            detail = "Configuracion SMTP incompleta"
            self.log_manager.log_system_event("SMTP_ERROR", "ALERTS", detail)
            return {"status": "Error", "message": detail}

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = sender
        message["To"] = recipient
        message.set_content(body)

        try:
            with smtplib.SMTP(host, port, timeout=15) as server:
                if starttls:
                    server.starttls()
                if user and password:
                    server.login(user, password)
                server.send_message(message)
            self._touch_cooldown(f"MAIL:{cooldown_key}")
            return {"status": "Enviado", "message": "Correo enviado correctamente"}
        except smtplib.SMTPAuthenticationError as exc:
            detail = f"Error de autenticacion SMTP: {exc}"
            self.log_manager.log_system_event("SMTP_ERROR", "ALERTS", detail)
            return {"status": "Error", "message": detail}
        except (smtplib.SMTPException, OSError) as exc:
            detail = f"Error de conexion SMTP: {exc}"
            self.log_manager.log_system_event("SMTP_ERROR", "ALERTS", detail)
            return {"status": "Error", "message": detail}

    def _unauthorized_body(self, alert: dict[str, str]) -> str:
        return "\n".join(
            [
                "Alerta de Equipo No Autorizado",
                "",
                f"Fecha y hora: {alert['date']} {alert['time']}",
                f"IP origen: {alert['src_ip']}",
                f"MAC origen: {alert['src_mac']}",
                f"Motivo: {alert['risk_type']}",
                f"Severidad: {alert['severity']}",
                f"Mensaje: {alert['message']}",
                "",
                "Recomendacion: Verifique si el equipo pertenece a la organizacion antes de autorizarlo.",
            ]
        )

    def _blacklist_body(self, alert: dict[str, str], indicator: dict, forensic_result: dict | None = None) -> str:
        forensic_result = forensic_result or {}
        return "\n".join(
            [
                "ALERTA DE EMERGENCIA - IP PELIGROSA DETECTADA",
                "",
                "Datos de red",
                f"Fecha y hora: {alert['date']} {alert['time']}",
                f"IP origen: {alert['src_ip']}",
                f"MAC origen: {alert['src_mac']}",
                f"IP destino peligrosa: {alert['dst_ip']}",
                "",
                "Riesgo",
                f"Tipo de riesgo: {indicator.get('risk_type', alert['risk_type'])}",
                f"Severidad: {alert['severity']}",
                f"Fuente: {indicator.get('source', 'N/D')}",
                f"Descripcion: {indicator.get('description', 'N/D')}",
                "",
                "Informacion forense",
                f"ASN: {forensic_result.get('asn') or 'N/D'}",
                f"Pais: {forensic_result.get('country') or 'N/D'}",
                f"Proveedor: {forensic_result.get('provider') or 'N/D'}",
                f"Abuse contact: {forensic_result.get('abuse_contact') or 'No se encontro contacto de abuso en la consulta WHOIS.'}",
                "",
                "Recomendacion: Bloquear IP temporalmente, revisar equipo origen y reportar al abuse contact si procede.",
                "",
                "Aviso: Esta alerta fue generada automaticamente por el IDS Institucional.",
            ]
        )

    def _generic_body(self, alert: dict[str, str]) -> str:
        return "\n".join(f"{key}: {value}" for key, value in alert.items())

    def _is_in_cooldown(self, key: str) -> bool:
        previous = self._last_sent_by_key.get(key)
        return bool(previous and (datetime.now() - previous).total_seconds() < self.cooldown_seconds())

    def _touch_cooldown(self, key: str) -> None:
        self._last_sent_by_key[key] = datetime.now()

    def _env_bool(self, key: str, default: bool) -> bool:
        value = os.getenv(key)
        if value is None:
            return default
        return value.strip().lower() in ["1", "true", "yes", "on", "si"]

    def _env_int(self, key: str, default: int) -> int:
        try:
            return int(os.getenv(key, str(default)))
        except ValueError:
            return default
