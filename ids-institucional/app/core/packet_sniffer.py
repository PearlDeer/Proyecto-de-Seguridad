from collections.abc import Callable
import ipaddress
import threading
from pathlib import Path

from app.core.alert_manager import AlertManager
from app.core.dns_monitor import DNSMonitor
from app.core.threat_intel import ThreatIntelService
from app.core.whitelist_manager import WhitelistManager


EventCallback = Callable[[dict[str, str]], None]
ErrorCallback = Callable[[str], None]


class PacketSniffer:
    """Captura paquetes DNS con Scapy en un hilo separado."""

    CAPTURE_FILTER = None
    PERMISSION_MESSAGE = (
        "No se pudo iniciar la captura. Ejecuta la aplicacion con permisos adecuados "
        "o configura capacidades para Python."
    )
    SCAPY_MISSING_MESSAGE = (
        "Scapy no esta instalado en el interprete actual. Scapy no es Scrapy; "
        "Scrapy es otra libreria. Ejecuta la aplicacion con "
        "venv/bin/python main.py o instala dependencias con venv/bin/python -m pip install -r requirements.txt."
    )

    def __init__(
        self,
        interface: str,
        event_callback: EventCallback | None = None,
        error_callback: ErrorCallback | None = None,
        dns_monitor: DNSMonitor | None = None,
        alert_callback: EventCallback | None = None,
        base_path: Path | None = None,
    ):
        self.interface = interface
        self.event_callback = event_callback
        self.error_callback = error_callback
        self.dns_monitor = dns_monitor or DNSMonitor()
        self.alert_callback = alert_callback
        self.whitelist = WhitelistManager(base_path) if base_path else None
        self.threat_intel = ThreatIntelService(base_path) if base_path else None
        self.alert_manager = AlertManager(base_path) if base_path else None
        self.enabled = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def status(self) -> str:
        return "activo" if self.enabled else "inactivo"

    def start(self) -> None:
        if self.enabled:
            return

        self._stop_event.clear()
        self.enabled = True
        self._thread = threading.Thread(target=self._capture_loop, name="IDS-DNS-Sniffer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self.enabled = False

    def _capture_loop(self) -> None:
        try:
            from scapy.all import sniff
        except ImportError:
            self._notify_error(self.SCAPY_MISSING_MESSAGE)
            return
        except PermissionError:
            self._notify_error(self.PERMISSION_MESSAGE)
            return
        except OSError as exc:
            message = str(exc).lower()
            if "permission" in message or "operation not permitted" in message:
                self._notify_error(self.PERMISSION_MESSAGE)
            else:
                self._notify_error(f"No se pudo inicializar Scapy: {exc}")
            return
        except Exception as exc:
            self._notify_error(f"No se pudo inicializar Scapy correctamente: {exc}")
            return

        try:
            while not self._stop_event.is_set():
                sniff(
                    iface=self.interface or None,
                    filter=self.CAPTURE_FILTER,
                    prn=self._handle_packet,
                    store=False,
                    timeout=1,
                )
        except PermissionError:
            self._notify_error(self.PERMISSION_MESSAGE)
        except OSError as exc:
            message = str(exc).lower()
            if "permission" in message or "operation not permitted" in message:
                self._notify_error(self.PERMISSION_MESSAGE)
            else:
                self._notify_error(f"No se pudo iniciar la captura en {self.interface}: {exc}")
        except Exception as exc:
            self._notify_error(f"Error durante la captura DNS: {exc}")
        finally:
            self.enabled = False

    def _handle_packet(self, packet) -> None:
        try:
            event = self.dns_monitor.parse_domain_event(packet)
            if event and self.event_callback:
                self.event_callback(event)
            self._inspect_security(packet)
        except Exception as exc:
            if self.error_callback:
                self.error_callback(f"Error procesando paquete capturado: {exc}")

    def _notify_error(self, message: str) -> None:
        self.enabled = False
        if self.error_callback:
            self.error_callback(message)

    def _inspect_security(self, packet) -> None:
        if not self.whitelist or not self.threat_intel or not self.alert_manager:
            return

        try:
            from scapy.layers.inet import IP
            from scapy.layers.l2 import Ether

            if not packet.haslayer(IP):
                return
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_mac = packet[Ether].src.upper() if packet.haslayer(Ether) else ""

            if src_ip and src_mac:
                authorization = self.whitelist.is_authorized(src_ip, src_mac)
                if not authorization.get("authorized", False):
                    alert = self.alert_manager.create_unauthorized_device_alert(authorization, src_ip, src_mac, dst_ip)
                    self._emit_alert(alert)

            if self._is_external_ip(dst_ip):
                result = self.threat_intel.lookup_local(dst_ip)
                if result.get("found"):
                    alert = self.alert_manager.create_blacklist_alert(src_ip, src_mac, dst_ip, result["indicator"])
                    self._emit_alert(alert)
        except Exception as exc:
            if self.error_callback:
                self.error_callback(f"Error inspeccionando seguridad del paquete: {exc}")

    def _emit_alert(self, alert: dict[str, str] | None) -> None:
        if alert and self.alert_callback:
            self.alert_callback(alert)

    def _is_external_ip(self, ip: str) -> bool:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified)
