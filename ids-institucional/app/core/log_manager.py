import csv
from pathlib import Path

from app.utils.config_loader import (
    ALERT_HEADERS,
    FORENSIC_HEADERS,
    SYSTEM_EVENT_HEADERS,
    TRAFFIC_HEADERS,
    ensure_csv,
    now_parts,
    read_csv,
)


class LogManager:
    def __init__(self, base_path: Path):
        self.logs_path = base_path / "logs"
        ensure_csv(self.traffic_path, TRAFFIC_HEADERS, [])
        ensure_csv(self.alerts_path, ALERT_HEADERS, [])
        ensure_csv(self.forensic_path, FORENSIC_HEADERS, [])
        ensure_csv(self.system_events_path, SYSTEM_EVENT_HEADERS, [])

    @property
    def traffic_path(self) -> Path:
        return self.logs_path / "traffic_log.csv"

    @property
    def alerts_path(self) -> Path:
        return self.logs_path / "alerts_log.csv"

    @property
    def forensic_path(self) -> Path:
        return self.logs_path / "forensic_log.csv"

    @property
    def system_events_path(self) -> Path:
        return self.logs_path / "system_events.csv"

    def traffic_rows(self) -> list[dict[str, str]]:
        return read_csv(self.traffic_path, TRAFFIC_HEADERS)

    def log_dns_event(self, event: dict[str, str]) -> None:
        self.append_row(self.traffic_path, TRAFFIC_HEADERS, event)

    def build_test_dns_event(self) -> dict[str, str]:
        date, time = now_parts()
        return {
            "date": date,
            "time": time,
            "src_ip": "192.168.1.50",
            "src_mac": "AA:BB:CC:DD:EE:FF",
            "domain": "ejemplo-institucional.local",
            "protocol": "DNS",
            "event_type": "DNS_QUERY",
        }

    def alert_rows(self) -> list[dict[str, str]]:
        return read_csv(self.alerts_path, ALERT_HEADERS)

    def log_alert(self, alert: dict[str, str]) -> None:
        self.append_row(self.alerts_path, ALERT_HEADERS, alert)

    def mark_alert_reviewed(self, alert: dict[str, str]) -> None:
        rows = self.alert_rows()
        for row in rows:
            if all(
                row.get(key, "") == alert.get(key, "")
                for key in ["date", "time", "severity", "src_ip", "src_mac", "dst_ip", "risk_type", "message"]
            ):
                row["status"] = "Revisada"
                break
        self._write_rows(self.alerts_path, ALERT_HEADERS, rows)

    def forensic_rows(self) -> list[dict[str, str]]:
        return read_csv(self.forensic_path, FORENSIC_HEADERS)

    def log_forensic_result(self, result: dict[str, str]) -> None:
        self.append_row(self.forensic_path, FORENSIC_HEADERS, result)

    def system_event_rows(self) -> list[dict[str, str]]:
        return read_csv(self.system_events_path, SYSTEM_EVENT_HEADERS)

    def last_system_event(self, module: str | None = None) -> dict[str, str] | None:
        rows = self.system_event_rows()
        if module:
            rows = [row for row in rows if row.get("module") == module]
        return rows[-1] if rows else None

    def log_system_event(self, event_type: str, module: str, message: str) -> None:
        date, time = now_parts()
        self.append_row(
            self.system_events_path,
            SYSTEM_EVENT_HEADERS,
            {
                "date": date,
                "time": time,
                "event_type": event_type,
                "module": module,
                "message": message,
            },
        )

    def append_row(self, path: Path, headers: list[str], row: dict[str, str]) -> None:
        ensure_csv(path, headers, [])
        with path.open("a", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=headers)
            writer.writerow({header: row.get(header, "") for header in headers})

    def _write_rows(self, path: Path, headers: list[str], rows: list[dict[str, str]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=headers)
            writer.writeheader()
            writer.writerows({header: row.get(header, "") for header in headers} for row in rows)
