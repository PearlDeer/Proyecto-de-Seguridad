import socket
from pathlib import Path


def get_hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "desconocido"


def get_local_ip_hint() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def list_network_interfaces() -> list[str]:
    interfaces: list[str] = []

    try:
        from scapy.all import get_if_list

        interfaces = [name for name in get_if_list() if name]
    except Exception:
        interfaces = []

    if not interfaces:
        sys_class_net = Path("/sys/class/net")
        try:
            interfaces = sorted(path.name for path in sys_class_net.iterdir() if path.name)
        except OSError:
            interfaces = []

    preferred = [name for name in interfaces if name != "lo"]
    return preferred + [name for name in interfaces if name == "lo"]
