class PacketSniffer:
    """Stub de captura para fases posteriores con Scapy/libpcap."""

    def __init__(self, interface: str, enabled: bool = False):
        self.interface = interface
        self.enabled = enabled

    def status(self) -> str:
        return "activo" if self.enabled else "inactivo"

    def start(self) -> None:
        # En fases posteriores aqui se integrara sniff() de Scapy con permisos controlados.
        self.enabled = True

    def stop(self) -> None:
        self.enabled = False
