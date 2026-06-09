"""
HTTP file extraction from reassembled TCP streams.

Scans accumulated TCP payload bytes for HTTP/1.x 200 responses whose
Content-Type or Content-Disposition indicates a file transfer, then
extracts the body, computes SHA-256, and optionally saves to disk.
"""
import hashlib
import os
import re
from collections import defaultdict

# Content-Type prefixes that indicate a binary/file payload
_FILE_TYPES = {
    'application/octet-stream',
    'application/x-msdownload',
    'application/x-executable',
    'application/x-dosexec',
    'application/zip',
    'application/x-zip-compressed',
    'application/x-rar-compressed',
    'application/x-7z-compressed',
    'application/x-tar',
    'application/gzip',
    'application/pdf',
    'application/java-archive',
    'application/vnd.ms-excel',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats',
    'application/x-msdos-program',
}

_MAX_STREAM_BYTES = 4 * 1024 * 1024   # 4 MB per stream
_MAX_FILE_BYTES   = 8 * 1024 * 1024   # 8 MB per extracted file


def _parse_response_headers(raw: bytes) -> tuple[str, dict]:
    """Return (status_line, headers_dict) from the bytes before \\r\\n\\r\\n."""
    try:
        text = raw.decode('utf-8', errors='replace')
        lines = text.split('\r\n')
        status_line = lines[0]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ':' in line:
                k, _, v = line.partition(':')
                headers[k.lower().strip()] = v.strip()
        return status_line, headers
    except Exception:
        return '', {}


def _get_status_code(status_line: str) -> int:
    try:
        return int(status_line.split()[1])
    except (IndexError, ValueError):
        return 0


def _guess_filename(content_disposition: str, content_type: str) -> str:
    """Best-effort filename from headers."""
    if content_disposition:
        m = re.search(r'filename[*]?=["\']?([^"\';\r\n]+)', content_disposition, re.I)
        if m:
            name = m.group(1).strip().strip('"\'')
            return os.path.basename(name)[:80]

    ext_map = {
        'application/zip':          '.zip',
        'application/pdf':          '.pdf',
        'application/octet-stream': '.bin',
        'application/x-msdownload': '.exe',
        'application/x-dosexec':    '.exe',
        'application/gzip':         '.gz',
        'application/java-archive': '.jar',
    }
    ct = content_type.lower()
    for k, ext in ext_map.items():
        if k in ct:
            return f'extracted{ext}'
    return 'extracted.bin'


def _is_file_transfer(content_type: str, content_disposition: str) -> bool:
    ct = content_type.lower()
    # Explicit attachment
    if 'attachment' in content_disposition.lower():
        return True
    # Known binary content types
    for ft in _FILE_TYPES:
        if ct.startswith(ft):
            return True
    # Images (sometimes embedded malware)
    if ct.startswith('image/') and not ct.startswith('image/svg'):
        return True
    return False


def extract_http_files(tcp_streams: dict, output_dir: str | None = None) -> list[dict]:
    """
    Scan reassembled TCP streams for HTTP file transfers.

    Args:
        tcp_streams:  dict mapping (src, dst, sport, dport) -> bytes/bytearray
        output_dir:   if given, extracted file bytes are written here

    Returns:
        List of file metadata dicts:
            filename, content_type, size, sha256, src, dst, truncated, [saved_path]
    """
    extracted: list[dict] = []

    for (src, dst, sport, dport), stream_data in tcp_streams.items():
        data = bytes(stream_data)
        pos = 0

        while pos < len(data):
            idx = data.find(b'HTTP/1.', pos)
            if idx == -1:
                break

            hdr_end = data.find(b'\r\n\r\n', idx)
            if hdr_end == -1:
                break

            status_line, headers = _parse_response_headers(data[idx:hdr_end])
            code = _get_status_code(status_line)
            body_start = hdr_end + 4

            if code not in (200, 206):
                pos = body_start
                continue

            content_type = headers.get('content-type', '').split(';')[0].strip()
            content_disp = headers.get('content-disposition', '')
            try:
                content_length = int(headers.get('content-length', '0'))
            except ValueError:
                content_length = 0

            if not _is_file_transfer(content_type, content_disp):
                pos = body_start + max(content_length, 1)
                continue

            # Extract body bytes
            cap = min(content_length or _MAX_FILE_BYTES, _MAX_FILE_BYTES)
            body = data[body_start:body_start + cap]

            if len(body) < 4:
                pos = body_start + max(content_length, 1)
                continue

            sha256   = hashlib.sha256(body).hexdigest()
            filename = _guess_filename(content_disp, content_type)

            info: dict = {
                'filename':     filename,
                'content_type': content_type,
                'size':         len(body),
                'sha256':       sha256,
                'src':          src,
                'dst':          dst,
                'truncated':    content_length > _MAX_FILE_BYTES,
            }

            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                safe = re.sub(r'[^\w.\-]', '_', f"{sha256[:12]}_{filename}")[:64]
                save_path = os.path.join(output_dir, safe)
                try:
                    with open(save_path, 'wb') as fh:
                        fh.write(body)
                    info['saved_path'] = save_path
                except OSError:
                    pass

            extracted.append(info)
            pos = body_start + max(content_length, 1)

    return extracted


def build_tcp_streams(
    packet_tuples: list,
    max_per_stream: int = _MAX_STREAM_BYTES,
) -> dict:
    """
    Build a TCP stream dict from an iterable of (src, dst, sport, dport, payload).
    Caps each stream at *max_per_stream* bytes to bound memory use.
    """
    streams: dict = defaultdict(bytearray)
    for src, dst, sport, dport, payload in packet_tuples:
        key = (src, dst, sport, dport)
        if len(streams[key]) < max_per_stream:
            streams[key].extend(payload)
    return dict(streams)
