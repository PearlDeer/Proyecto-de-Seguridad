from pathlib import Path

from app.utils.config_loader import read_json, write_json
from app.utils.validators import is_valid_ip, normalize_ip


class ThreatIntelService:
    def __init__(self, base_path: Path):
        self.path = base_path / "data" / "blacklist_ips.json"

    def indicators(self) -> list[dict]:
        data = read_json(self.path, [])
        return data if isinstance(data, list) else []

    def save_indicators(self, indicators: list[dict]) -> None:
        ordered = sorted(indicators, key=lambda item: item.get("ip", ""))
        write_json(self.path, ordered)

    def lookup_local(self, ip: str) -> dict:
        if not is_valid_ip(ip):
            return {"found": False, "message": "IP invalida para consulta."}
        normalized_ip = normalize_ip(ip)
        for indicator in self.indicators():
            if indicator.get("ip") == normalized_ip:
                return {"found": True, "indicator": indicator}
        return {"found": False, "message": "La IP no aparece en la blacklist local."}

    def add_indicator(self, ip: str, risk_type: str, severity: str, source: str, description: str) -> tuple[bool, str]:
        valid, message = self._validate_indicator(ip, risk_type, severity, source, description)
        if not valid:
            return False, message
        normalized_ip = normalize_ip(ip)
        indicators = self.indicators()
        if any(item.get("ip") == normalized_ip for item in indicators):
            return False, "La IP ya existe en la blacklist."
        indicators.append(self._indicator_payload(normalized_ip, risk_type, severity, source, description))
        self.save_indicators(indicators)
        return True, "IP peligrosa agregada correctamente."

    def update_indicator(self, original_ip: str, ip: str, risk_type: str, severity: str, source: str, description: str) -> tuple[bool, str]:
        valid, message = self._validate_indicator(ip, risk_type, severity, source, description)
        if not valid:
            return False, message
        original = normalize_ip(original_ip)
        normalized_ip = normalize_ip(ip)
        indicators = self.indicators()
        for indicator in indicators:
            if indicator.get("ip") != original and indicator.get("ip") == normalized_ip:
                return False, "La IP ya existe en la blacklist."
        for indicator in indicators:
            if indicator.get("ip") == original:
                indicator.update(self._indicator_payload(normalized_ip, risk_type, severity, source, description))
                self.save_indicators(indicators)
                return True, "IP peligrosa editada correctamente."
        return False, "No se encontro la IP seleccionada."

    def delete_indicator(self, ip: str) -> tuple[bool, str]:
        normalized_ip = normalize_ip(ip) if is_valid_ip(ip) else ip.strip()
        indicators = self.indicators()
        filtered = [item for item in indicators if item.get("ip") != normalized_ip]
        if len(filtered) == len(indicators):
            return False, "No se encontro la IP seleccionada."
        self.save_indicators(filtered)
        return True, "IP peligrosa eliminada correctamente."

    def _validate_indicator(self, ip: str, risk_type: str, severity: str, source: str, description: str) -> tuple[bool, str]:
        if not is_valid_ip(ip):
            return False, "La IP es invalida."
        if not risk_type.strip():
            return False, "Falta el tipo de riesgo."
        if not severity.strip():
            return False, "Falta la severidad."
        if not source.strip():
            return False, "Falta la fuente."
        if not description.strip():
            return False, "Falta la descripcion."
        return True, "Datos validos."

    def _indicator_payload(self, ip: str, risk_type: str, severity: str, source: str, description: str) -> dict[str, str]:
        return {
            "ip": ip,
            "risk_type": risk_type.strip(),
            "severity": severity.strip().upper(),
            "source": source.strip(),
            "description": description.strip(),
        }
