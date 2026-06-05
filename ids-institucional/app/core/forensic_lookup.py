from datetime import datetime


class ForensicLookupService:
    """Servicio base para futuras consultas WHOIS, ASN y Abuse contact."""

    def build_simulated_result(self, ip: str) -> dict[str, str]:
        now = datetime.now()
        return {
            "date": now.strftime("%Y-%m-%d"),
            "time": now.strftime("%H:%M:%S"),
            "ip": ip,
            "asn": "Pendiente",
            "country": "Pendiente",
            "abuse_contact": "Configurar consulta WHOIS",
            "provider": "No consultado en fase 1",
            "raw_summary": "Resultado simulado; la integracion real se habilitara en fases posteriores.",
        }
