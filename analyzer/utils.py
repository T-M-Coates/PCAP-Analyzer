import base64
import ipaddress
import socket

PCAP_MAGIC   = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4')
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'   # Section Header Block type

_PRIVATE_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]


def ip_to_str(ip_bytes: bytes) -> str:
    try:
        return socket.inet_ntoa(ip_bytes)
    except Exception:
        return ip_bytes.hex()


def is_internal(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def try_decode_b64(s: str) -> dict:
    result = {"raw": s, "utf8": None, "utf16le": None}
    try:
        # Pad to valid base64 length
        padded = s + '=' * (-len(s) % 4)
        raw_bytes = base64.b64decode(padded, validate=False)
        try:
            result["utf8"] = raw_bytes.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            pass
        try:
            decoded = raw_bytes.decode("utf-16-le")
            # Only keep if it looks like real text (printable ascii ratio > 0.7)
            printable = sum(1 for c in decoded if c.isprintable())
            if len(decoded) > 0 and printable / len(decoded) > 0.7:
                result["utf16le"] = decoded
        except (UnicodeDecodeError, ValueError):
            pass
    except Exception:
        pass
    return result


def parse_http_headers(payload_bytes: bytes) -> dict:
    headers = {}
    try:
        header_section = payload_bytes.split(b'\r\n\r\n', 1)[0]
        lines = header_section.split(b'\r\n')[1:]  # skip request line
        for line in lines:
            if b':' in line:
                key, _, val = line.partition(b':')
                headers[key.strip().decode('latin-1').lower()] = val.strip().decode('latin-1', errors='replace')
    except Exception:
        pass
    return headers


def pcap_magic_valid(path: str) -> bool:
    """Return True if the file starts with a known PCAP or PCAPNG magic."""
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
        return magic in PCAP_MAGIC or magic == PCAPNG_MAGIC
    except OSError:
        return False


def is_pcapng(path: str) -> bool:
    """Return True if the file is pcapng format (Section Header Block magic)."""
    try:
        with open(path, 'rb') as f:
            return f.read(4) == PCAPNG_MAGIC
    except OSError:
        return False
