from datetime import datetime
from pathlib import Path

from app.core.log_manager import LogManager
from app.utils.config_loader import read_json, write_json
from app.utils.validators import is_valid_ip, is_valid_mac, normalize_ip, normalize_mac


class WhitelistManager:
    def __init__(self, base_path: Path):
        self.path = base_path / "data" / "whitelist.json"
        self.log_manager = LogManager(base_path)

    def all_devices(self) -> list[dict]:
        data = read_json(self.path, [])
        return data if isinstance(data, list) else []

    def _save_devices(self, devices: list[dict]) -> None:
        ordered = sorted(devices, key=lambda item: int(item.get("id", 0)))
        write_json(self.path, ordered)

    def _validate_device(self, device_name: str, ip: str, mac: str, exclude_id: int | None = None) -> tuple[bool, str]:
        if not device_name.strip():
            return False, "Falta el nombre del equipo."
        if not is_valid_ip(ip):
            return False, "La IP es invalida."
        if not is_valid_mac(mac):
            return False, "La MAC es invalida."

        normalized_ip = normalize_ip(ip)
        normalized_mac = normalize_mac(mac)
        for device in self.all_devices():
            current_id = int(device.get("id", 0))
            if exclude_id is not None and current_id == exclude_id:
                continue
            if device.get("ip") == normalized_ip:
                return False, "La IP ya existe."
            if normalize_mac(str(device.get("mac", ""))) == normalized_mac:
                return False, "La MAC ya existe."
        return True, "Datos validos."

    def add_device(self, device_name: str, ip: str, mac: str, description: str = "") -> tuple[bool, str]:
        valid, message = self._validate_device(device_name, ip, mac)
        if not valid:
            return False, message

        devices = self.all_devices()
        next_id = max((int(item.get("id", 0)) for item in devices), default=0) + 1
        device = {
            "id": next_id,
            "device_name": device_name.strip(),
            "ip": normalize_ip(ip),
            "mac": normalize_mac(mac),
            "description": description.strip(),
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        devices.append(device)
        self._save_devices(devices)
        self.log_manager.log_system_event("CREATE", "WHITELIST", f"Equipo autorizado agregado: {device['device_name']}")
        return True, "Equipo agregado correctamente."

    def update_device(self, device_id: int, device_name: str, ip: str, mac: str, description: str = "") -> tuple[bool, str]:
        valid, message = self._validate_device(device_name, ip, mac, exclude_id=device_id)
        if not valid:
            return False, message

        devices = self.all_devices()
        for device in devices:
            if int(device.get("id", 0)) == device_id:
                device.update(
                    {
                        "device_name": device_name.strip(),
                        "ip": normalize_ip(ip),
                        "mac": normalize_mac(mac),
                        "description": description.strip(),
                    }
                )
                self._save_devices(devices)
                self.log_manager.log_system_event("UPDATE", "WHITELIST", f"Equipo autorizado editado: {device['device_name']}")
                return True, "Equipo editado correctamente."
        return False, "No se encontro el equipo seleccionado."

    def delete_device(self, device_id: int) -> tuple[bool, str]:
        devices = self.all_devices()
        removed = next((item for item in devices if int(item.get("id", 0)) == device_id), None)
        if removed is None:
            return False, "No se encontro el equipo seleccionado."

        self._save_devices([item for item in devices if int(item.get("id", 0)) != device_id])
        self.log_manager.log_system_event("DELETE", "WHITELIST", f"Equipo autorizado eliminado: {removed.get('device_name', 'Sin nombre')}")
        return True, "Equipo eliminado correctamente."

    def is_authorized(self, ip: str, mac: str) -> dict:
        normalized_ip = normalize_ip(ip) if is_valid_ip(ip) else ip.strip()
        normalized_mac = normalize_mac(mac) if is_valid_mac(mac) else mac.strip().upper()
        ip_match = None
        mac_match = None

        for device in self.all_devices():
            if device.get("ip") == normalized_ip:
                ip_match = device
            if normalize_mac(str(device.get("mac", ""))) == normalized_mac:
                mac_match = device

        if ip_match and mac_match and ip_match.get("id") == mac_match.get("id"):
            return {"authorized": True, "reason": "AUTHORIZED", "device": ip_match}
        if ip_match:
            return {"authorized": False, "reason": "UNKNOWN_MAC", "device": ip_match}
        if mac_match:
            return {"authorized": False, "reason": "UNKNOWN_IP", "device": mac_match}
        return {"authorized": False, "reason": "UNKNOWN_DEVICE", "device": None}
