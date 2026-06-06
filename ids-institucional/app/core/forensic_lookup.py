from pathlib import Path
import re
import subprocess

from app.core.log_manager import LogManager
from app.utils.config_loader import now_parts
from app.utils.validators import is_valid_ip, normalize_ip


NO_ABUSE_CONTACT = "No se encontro contacto de abuso en la consulta WHOIS."


class ForensicLookupService:
    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.log_manager = LogManager(base_path)

    def lookup_ip(self, ip: str) -> dict:
        if not is_valid_ip(ip):
            result = self._empty_result(ip)
            result["error"] = "IP invalida para consulta WHOIS."
            self.save_forensic_result(result)
            return result

        normalized_ip = normalize_ip(ip)
        try:
            raw_text = self._run_whois(normalized_ip)
            result = {
                "ip": normalized_ip,
                "asn": self._extract_first(raw_text, ["origin", "originas", "asn", "aut-num"]),
                "country": self._extract_first(raw_text, ["country"]),
                "provider": self._extract_first(raw_text, ["orgname", "organisation", "organization", "netname", "descr", "owner"]),
                "abuse_contact": self.extract_abuse_contact(raw_text),
                "raw_summary": self._summarize_raw(raw_text),
                "success": True,
                "error": "",
            }
            if not result["abuse_contact"]:
                result["abuse_contact"] = NO_ABUSE_CONTACT
            self.save_forensic_result(result)
            return result
        except Exception as exc:
            result = self._empty_result(normalized_ip)
            result["error"] = f"WHOIS fallo: {exc}"
            result["raw_summary"] = result["error"]
            self.save_forensic_result(result)
            self.log_manager.log_system_event("ERROR", "FORENSIC", result["error"])
            return result

    def extract_abuse_contact(self, raw_text: str) -> str:
        abuse_lines = []
        for line in raw_text.splitlines():
            lower = line.lower()
            if "abuse" in lower or "e-mail" in lower or "email" in lower:
                emails = re.findall(r"[\w.\-+%]+@[\w.\-]+\.[A-Za-z]{2,}", line)
                abuse_lines.extend(emails)
        if abuse_lines:
            unique = []
            for email in abuse_lines:
                if email not in unique:
                    unique.append(email)
            return ", ".join(unique[:5])
        return ""

    def save_forensic_result(self, result: dict) -> None:
        date, time = now_parts()
        row = {
            "date": date,
            "time": time,
            "ip": result.get("ip", ""),
            "asn": result.get("asn", ""),
            "country": result.get("country", ""),
            "abuse_contact": result.get("abuse_contact", ""),
            "provider": result.get("provider", ""),
            "raw_summary": result.get("raw_summary", ""),
        }
        self.log_manager.log_forensic_result(row)

    def build_forensic_summary(self, result: dict) -> str:
        return "\n".join(
            [
                "Informacion forense WHOIS/Abuse",
                f"IP consultada: {result.get('ip', 'N/D')}",
                f"ASN: {result.get('asn') or 'N/D'}",
                f"Pais: {result.get('country') or 'N/D'}",
                f"Proveedor/organizacion: {result.get('provider') or 'N/D'}",
                f"Abuse contact: {result.get('abuse_contact') or NO_ABUSE_CONTACT}",
                f"Estado: {'Correcto' if result.get('success') else 'Error'}",
                f"Error: {result.get('error') or 'N/D'}",
            ]
        )

    def latest_for_ip(self, ip: str) -> dict[str, str] | None:
        normalized_ip = normalize_ip(ip) if is_valid_ip(ip) else ip.strip()
        rows = [row for row in self.log_manager.forensic_rows() if row.get("ip") == normalized_ip]
        return rows[-1] if rows else None

    def demo_lookup(self) -> dict:
        result = {
            "ip": "185.220.101.45",
            "asn": "AS60729",
            "country": "DE",
            "provider": "Proveedor de ejemplo para demostracion",
            "abuse_contact": "abuse@example.org",
            "raw_summary": "Resultado WHOIS simulado para presentacion presencial.",
            "success": True,
            "error": "",
        }
        self.save_forensic_result(result)
        return result

    def _run_whois(self, ip: str) -> str:
        completed = subprocess.run(
            ["whois", ip],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        raw = completed.stdout.strip() or completed.stderr.strip()
        if not raw:
            raise RuntimeError("whois no devolvio informacion.")
        return raw

    def _extract_first(self, raw_text: str, keys: list[str]) -> str:
        for line in raw_text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            normalized_key = key.strip().lower()
            if normalized_key in keys:
                return value.strip()
        return ""

    def _summarize_raw(self, raw_text: str) -> str:
        interesting = []
        terms = ["origin", "asn", "country", "org", "netname", "descr", "abuse", "email", "e-mail"]
        for line in raw_text.splitlines():
            clean = line.strip()
            if clean and any(term in clean.lower() for term in terms):
                interesting.append(clean)
            if len(interesting) >= 10:
                break
        return " | ".join(interesting)[:900] if interesting else raw_text[:900]

    def _empty_result(self, ip: str) -> dict:
        return {
            "ip": ip,
            "asn": "",
            "country": "",
            "provider": "",
            "abuse_contact": NO_ABUSE_CONTACT,
            "raw_summary": "",
            "success": False,
            "error": "",
        }
