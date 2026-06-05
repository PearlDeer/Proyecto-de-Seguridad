from datetime import datetime
from pathlib import Path

from app.utils.config_loader import read_json, write_json
from app.utils.validators import is_valid_ip, is_valid_mac, normalize_mac


class WhitelistManager:
    def __init__(self, base_path: Path):
        self.path = base_path / "data" / "whitelist.json"

    def all_devices(self) -> list[dict]:
        data = read_json(self.path, [])
        return data if isinstance(data, list) else []

    def add_device(self, device_name: str, ip: str, mac: str, description: str = "") -> tuple[bool, str]:
        if not device_name.strip():
            return False, "El nombre del equipo es obligatorio."
        if not is_valid_ip(ip):
            return False, "La IP no tiene un formato valido."
        if not is_valid_mac(mac):
            return False, "La MAC no tiene un formato valido."

        devices = self.all_devices()
        next_id = max((int(item.get("id", 0)) for item in devices), default=0) + 1
        devices.append(
            {
                "id": next_id,
                "device_name": device_name.strip(),
                "ip": ip.strip(),
                "mac": normalize_mac(mac),
                "description": description.strip(),
                "created_at": datetime.now().isoformat(timespec="seconds"),
            }
        )
        write_json(self.path, devices)
        return True, "Equipo agregado a la lista blanca."

    def delete_device(self, device_id: int) -> None:
        devices = [item for item in self.all_devices() if int(item.get("id", 0)) != device_id]
        write_json(self.path, devices)
