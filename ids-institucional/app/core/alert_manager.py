from datetime import datetime
from pathlib import Path

from app.core.log_manager import LogManager
from app.utils.config_loader import ALERT_HEADERS


class AlertManager:
    def __init__(self, base_path: Path):
        self.log_manager = LogManager(base_path)

    def alerts(self) -> list[dict[str, str]]:
        return self.log_manager.alert_rows()

    def add_alert(self, severity: str, src_ip: str, src_mac: str, dst_ip: str, risk_type: str, message: str) -> None:
        now = datetime.now()
        self.log_manager.append_row(
            self.log_manager.alerts_path,
            ALERT_HEADERS,
            {
                "date": now.strftime("%Y-%m-%d"),
                "time": now.strftime("%H:%M:%S"),
                "severity": severity,
                "src_ip": src_ip,
                "src_mac": src_mac,
                "dst_ip": dst_ip,
                "risk_type": risk_type,
                "message": message,
                "status": "Nueva",
            },
        )
