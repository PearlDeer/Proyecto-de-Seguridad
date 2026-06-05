from pathlib import Path

from app.utils.config_loader import read_json
from app.utils.validators import is_valid_ip


class ThreatIntelService:
    def __init__(self, base_path: Path):
        self.path = base_path / "data" / "blacklist_ips.json"

    def indicators(self) -> list[dict]:
        data = read_json(self.path, [])
        return data if isinstance(data, list) else []

    def lookup_local(self, ip: str) -> dict:
        if not is_valid_ip(ip):
            return {"found": False, "message": "IP invalida para consulta."}
        for indicator in self.indicators():
            if indicator.get("ip") == ip:
                return {"found": True, "indicator": indicator}
        return {"found": False, "message": "La IP no aparece en la blacklist local."}
