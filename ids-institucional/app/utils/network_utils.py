import socket


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
