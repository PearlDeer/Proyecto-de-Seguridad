from app.utils.config_loader import now_parts


class DNSMonitor:
    """Extrae eventos de consultas DNS desde paquetes Scapy."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def parse_domain_event(self, packet) -> dict[str, str] | None:
        if not self.enabled:
            return None

        try:
            from scapy.layers.dns import DNS, DNSQR
            from scapy.layers.inet import IP
            from scapy.layers.l2 import Ether
        except ImportError:
            return None

        try:
            if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
                return None

            dns_layer = packet.getlayer(DNS)
            query_layer = packet.getlayer(DNSQR)
            if getattr(dns_layer, "qr", 1) != 0:
                return None

            raw_domain = getattr(query_layer, "qname", b"")
            domain = self._decode_qname(raw_domain)
            if not domain:
                return None

            date, time = now_parts()
            return {
                "date": date,
                "time": time,
                "src_ip": packet[IP].src if packet.haslayer(IP) else "",
                "src_mac": packet[Ether].src.upper() if packet.haslayer(Ether) else "",
                "domain": domain,
                "protocol": "DNS",
                "event_type": "DNS_QUERY",
            }
        except Exception:
            return None

    def _decode_qname(self, raw_domain: bytes | str) -> str:
        if isinstance(raw_domain, bytes):
            domain = raw_domain.decode("utf-8", errors="ignore")
        else:
            domain = str(raw_domain)
        return domain.strip().rstrip(".")
