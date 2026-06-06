import csv
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any


TRAFFIC_HEADERS = ["date", "time", "src_ip", "src_mac", "domain", "protocol", "event_type"]
ALERT_HEADERS = ["date", "time", "severity", "src_ip", "src_mac", "dst_ip", "risk_type", "message", "status"]
FORENSIC_HEADERS = ["date", "time", "ip", "asn", "country", "abuse_contact", "provider", "raw_summary"]
SYSTEM_EVENT_HEADERS = ["date", "time", "event_type", "module", "message"]


def now_parts() -> tuple[str, str]:
    current = datetime.now()
    return current.strftime("%Y-%m-%d"), current.strftime("%H:%M:%S")


def read_json(path: Path, default: Any) -> Any:
    try:
        if not path.exists() or path.stat().st_size == 0:
            write_json(path, default)
            return default
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        backup_path = path.with_suffix(f"{path.suffix}.bak")
        try:
            shutil.copy2(path, backup_path)
        except OSError:
            pass
        write_json(path, default)
        return default
    except OSError:
        write_json(path, default)
        return default


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, ensure_ascii=False)
        file.write("\n")


def read_csv(path: Path, headers: list[str]) -> list[dict[str, str]]:
    ensure_csv(path, headers, [])
    with path.open("r", encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def ensure_csv(path: Path, headers: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > 0:
        return
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def ensure_project_files(base_path: Path) -> None:
    data_path = base_path / "data"
    logs_path = base_path / "logs"
    (base_path / "assets" / "screenshots").mkdir(parents=True, exist_ok=True)

    date, time = now_parts()
    read_json(
        data_path / "whitelist.json",
        [
            {
                "id": 1,
                "device_name": "Servidor Institucional",
                "ip": "192.168.1.10",
                "mac": "00:11:22:33:44:55",
                "description": "Servidor autorizado de servicios internos",
                "created_at": f"{date}T{time}",
            },
            {
                "id": 2,
                "device_name": "Equipo Administracion",
                "ip": "192.168.1.25",
                "mac": "AA:BB:CC:DD:EE:01",
                "description": "Estacion de trabajo administrativa",
                "created_at": f"{date}T{time}",
            },
        ],
    )
    read_json(
        data_path / "blacklist_ips.json",
        [
            {
                "ip": "185.220.101.45",
                "risk_type": "Botnet",
                "severity": "EMERGENCY",
                "source": "Lista local de ejemplo",
                "description": "IP marcada para pruebas de correlacion defensiva",
            },
            {
                "ip": "203.0.113.66",
                "risk_type": "Malware",
                "severity": "CRITICAL",
                "source": "Threat feed simulado",
                "description": "Indicador reservado para validacion visual",
            },
        ],
    )
    read_json(
        data_path / "settings.json",
        {
            "admin_email": "seguridad@example.org",
            "capture_interface": "eth0",
            "monitoring_enabled": False,
            "dns_logging_enabled": True,
            "threat_intel_enabled": True,
            "smtp_enabled": False,
            "alert_cooldown_seconds": 300,
        },
    )
    ensure_csv(
        logs_path / "traffic_log.csv",
        TRAFFIC_HEADERS,
        [
            {
                "date": date,
                "time": time,
                "src_ip": "192.168.1.25",
                "src_mac": "AA:BB:CC:DD:EE:01",
                "domain": "debian.org",
                "protocol": "DNS",
                "event_type": "Consulta permitida",
            }
        ],
    )
    ensure_csv(
        logs_path / "alerts_log.csv",
        ALERT_HEADERS,
        [
            {
                "date": date,
                "time": time,
                "severity": "CRITICAL",
                "src_ip": "192.168.1.90",
                "src_mac": "DE:AD:BE:EF:00:10",
                "dst_ip": "185.220.101.45",
                "risk_type": "IP en blacklist",
                "message": "Conexion simulada hacia IP peligrosa",
                "status": "Nueva",
            }
        ],
    )
    ensure_csv(
        logs_path / "forensic_log.csv",
        FORENSIC_HEADERS,
        [
            {
                "date": date,
                "time": time,
                "ip": "185.220.101.45",
                "asn": "AS0000",
                "country": "N/D",
                "abuse_contact": "abuse@example.org",
                "provider": "Proveedor simulado",
                "raw_summary": "Registro de ejemplo para futura consulta WHOIS/Abuse.",
            }
        ],
    )
    ensure_csv(
        logs_path / "system_events.csv",
        SYSTEM_EVENT_HEADERS,
        [
            {
                "date": date,
                "time": time,
                "event_type": "INIT",
                "module": "WHITELIST",
                "message": "Modulo de lista blanca preparado para administracion IP/MAC.",
            }
        ],
    )
