"""
TLS certificate extraction and inspection.

Parses TLS Certificate handshake messages from raw TCP payloads and uses
the 'cryptography' library to analyse the X.509 certificate contents.
Flags: self-signed, expired, not-yet-valid, very-short validity, IP-address CN.
"""
import hashlib
import struct
from datetime import datetime, timezone

try:
    from cryptography import x509
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False


def _parse_cert_records(data: bytes) -> list[bytes]:
    """
    Walk TLS records in *data* looking for Certificate handshake messages.
    Returns a list of raw DER certificate bytes (may contain more than one
    certificate if the server sends a chain).
    """
    certs_der: list[bytes] = []
    pos = 0

    while pos + 5 <= len(data):
        record_type = data[pos]
        if record_type != 0x16:          # Handshake record
            pos += 1
            continue

        record_len = struct.unpack('>H', data[pos + 3:pos + 5])[0]
        payload_end = pos + 5 + record_len
        if payload_end > len(data):
            break
        record_body = data[pos + 5:payload_end]
        pos = payload_end

        if not record_body or record_body[0] != 0x0b:   # 0x0b = Certificate
            continue

        # Handshake header: type(1) + length(3) = 4 bytes
        if len(record_body) < 7:
            continue

        cert_list_len = struct.unpack('>I', b'\x00' + record_body[4:7])[0]
        cert_pos = 7

        while cert_pos + 3 <= min(7 + cert_list_len, len(record_body)):
            cert_len = struct.unpack('>I', b'\x00' + record_body[cert_pos:cert_pos + 3])[0]
            cert_pos += 3
            if cert_pos + cert_len > len(record_body):
                break
            der = record_body[cert_pos:cert_pos + cert_len]
            if der:
                certs_der.append(der)
            cert_pos += cert_len

    return certs_der


def extract_certificates(payload: bytes, src: str = '', dst: str = '') -> list[dict]:
    """
    Extract and analyse all TLS certificates found in *payload*.

    Returns a list of certificate-info dicts:
        cn, issuer_cn, not_before, not_after, validity_days,
        is_self_signed, is_expired, sans, fingerprint_sha256, flags, src, dst
    """
    if not _CRYPTO_OK:
        return []

    results: list[dict] = []
    seen_fps: set[str] = set()

    try:
        der_list = _parse_cert_records(payload)
    except Exception:
        return []

    for der in der_list:
        fp = hashlib.sha256(der).hexdigest()
        if fp in seen_fps:
            continue
        seen_fps.add(fp)

        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception:
            continue

        # Common Name
        cn = _get_cn(cert.subject)
        issuer_cn = _get_cn(cert.issuer)

        # Validity dates — cryptography ≥ 42 returns tz-aware datetimes
        now = datetime.now(timezone.utc)
        try:
            not_before = cert.not_valid_before_utc
            not_after  = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after  = cert.not_valid_after.replace(tzinfo=timezone.utc)

        validity_days = (not_after - not_before).days

        # Subject Alternative Names
        sans: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(v.value) for v in san_ext.value][:8]
        except Exception:
            pass

        # Flags
        flags: list[str] = []
        if cert.subject == cert.issuer:
            flags.append('SELF_SIGNED')
        if not_after < now:
            flags.append('EXPIRED')
        if not_before > now:
            flags.append('NOT_YET_VALID')
        if 0 < validity_days < 7:
            flags.append('SHORT_VALIDITY')
        if cn and _looks_like_ip(cn):
            flags.append('IP_ADDRESS_CN')

        results.append({
            'cn':                cn,
            'issuer_cn':         issuer_cn,
            'not_before':        not_before.isoformat(),
            'not_after':         not_after.isoformat(),
            'validity_days':     validity_days,
            'is_self_signed':    'SELF_SIGNED' in flags,
            'is_expired':        'EXPIRED' in flags,
            'sans':              sans,
            'fingerprint_sha256': fp,
            'flags':             flags,
            'src':               src,
            'dst':               dst,
        })

    return results


def is_suspicious_cert(cert_info: dict) -> bool:
    """Return True if the certificate carries any suspicious flag."""
    return bool(cert_info.get('flags'))


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_cn(name) -> str | None:
    try:
        attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else None
    except Exception:
        return None


def _looks_like_ip(s: str) -> bool:
    parts = s.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
