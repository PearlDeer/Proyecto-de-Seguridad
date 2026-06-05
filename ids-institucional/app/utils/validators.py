import ipaddress
import re


MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_mac(value: str) -> bool:
    return bool(MAC_PATTERN.match(value.strip()))


def normalize_mac(value: str) -> str:
    return value.strip().replace("-", ":").upper()
