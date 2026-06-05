class DNSMonitor:
    """Preparado para extraer dominios desde paquetes DNS en fases posteriores."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def parse_domain_event(self, packet) -> dict | None:
        # Stub deliberado: la fase 1 usa datos CSV reales y no captura paquetes.
        return None
