import csv
from pathlib import Path

from app.utils.config_loader import ALERT_HEADERS, FORENSIC_HEADERS, TRAFFIC_HEADERS, ensure_csv, read_csv


class LogManager:
    def __init__(self, base_path: Path):
        self.logs_path = base_path / "logs"
        ensure_csv(self.traffic_path, TRAFFIC_HEADERS, [])
        ensure_csv(self.alerts_path, ALERT_HEADERS, [])
        ensure_csv(self.forensic_path, FORENSIC_HEADERS, [])

    @property
    def traffic_path(self) -> Path:
        return self.logs_path / "traffic_log.csv"

    @property
    def alerts_path(self) -> Path:
        return self.logs_path / "alerts_log.csv"

    @property
    def forensic_path(self) -> Path:
        return self.logs_path / "forensic_log.csv"

    def traffic_rows(self) -> list[dict[str, str]]:
        return read_csv(self.traffic_path, TRAFFIC_HEADERS)

    def alert_rows(self) -> list[dict[str, str]]:
        return read_csv(self.alerts_path, ALERT_HEADERS)

    def forensic_rows(self) -> list[dict[str, str]]:
        return read_csv(self.forensic_path, FORENSIC_HEADERS)

    def append_row(self, path: Path, headers: list[str], row: dict[str, str]) -> None:
        ensure_csv(path, headers, [])
        with path.open("a", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=headers)
            writer.writerow({header: row.get(header, "") for header in headers})
