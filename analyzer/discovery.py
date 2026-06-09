from __future__ import annotations
import socket
import struct
from collections import defaultdict
from datetime import datetime

import dpkt

from .utils import ip_to_str, is_internal

_ARP_REQUEST = 1
_ARP_REPLY   = 2

_LLMNR_PORT = 5355
_MDNS_PORT  = 5353
_NBNS_PORT  = 137
_SSDP_PORT  = 1900
_LLDP_ETYPE = 0x88CC

# mDNS service type → (device_type, human_label)
_MDNS_SERVICES: dict[str, tuple[str, str]] = {
    '_axis-video':       ('iot',      'IP Camera (Axis)'),
    '_rtsp':             ('iot',      'Streaming Camera'),
    '_nvs':              ('iot',      'IP Camera (ONVIF)'),
    '_dahua':            ('iot',      'IP Camera (Dahua)'),
    '_hikvision':        ('iot',      'IP Camera (Hikvision)'),
    '_printer':          ('printer',  'Network Printer'),
    '_ipp':              ('printer',  'IPP Printer'),
    '_ipps':             ('printer',  'IPP Printer (TLS)'),
    '_pdl-datastream':   ('printer',  'Network Printer'),
    '_scanner':          ('printer',  'Network Scanner'),
    '_uscan':            ('printer',  'Network Scanner'),
    '_airplay':          ('iot',      'AirPlay Device'),
    '_raop':             ('iot',      'AirPlay Speaker'),
    '_googlecast':       ('iot',      'Chromecast / Google Cast'),
    '_homekit':          ('iot',      'HomeKit Device'),
    '_hue':              ('iot',      'Philips Hue'),
    '_elg':              ('iot',      'Elgato Device'),
    '_spotify-connect':  ('iot',      'Spotify Connect Device'),
    '_daap':             ('iot',      'iTunes / Music Server'),
    '_nvstream':         ('iot',      'NVIDIA GameStream'),
    '_androidtvremote':  ('iot',      'Android TV'),
    '_amzn-wplay':       ('iot',      'Amazon Fire TV'),
    '_roku':             ('iot',      'Roku Streaming Device'),
    '_wemo':             ('iot',      'Belkin WeMo Device'),
    '_matter':           ('iot',      'Matter Smart Home Device'),
    '_smb':              ('computer', 'SMB File Server'),
    '_afpovertcp':       ('computer', 'Mac File Server (AFP)'),
    '_workstation':      ('computer', 'Workstation'),
    '_ssh':              ('server',   'SSH Server'),
    '_ftp':              ('server',   'FTP Server'),
    '_http':             ('server',   'HTTP Server'),
    '_https':            ('server',   'HTTPS Server'),
    '_nfs':              ('server',   'NFS Server'),
    '_postgresql':       ('server',   'PostgreSQL Server'),
    '_mysql':            ('server',   'MySQL Server'),
}

# DHCP Vendor Class Identifier (option 60) substring → (device_type, human_label)
# Checked case-insensitively; more specific strings must come first.
_DHCP_VENDOR_PATTERNS: list[tuple[str, str, str]] = [
    ('android-dhcp',    'mobile',   'Android Device'),
    ('MSFT 5.0',        'computer', 'Windows 10/11 PC'),
    ('MSFT',            'computer', 'Windows PC'),
    ('iphone',          'mobile',   'iPhone'),
    ('ipad',            'mobile',   'iPad'),
    ('appletv',         'iot',      'Apple TV'),
    ('homepod',         'iot',      'HomePod'),
    ('apple',           'computer', 'Apple Device'),
    ('udhcpc',          'iot',      'Embedded Linux Device'),
    ('dhcpcd',          'computer', 'Linux PC'),
    ('cisco',           'switch',   'Cisco Device'),
]

# HTTP User-Agent substring → (device_type, human_label)
_UA_PATTERNS: list[tuple[str, str, str]] = [
    ('windows nt 10',          'computer', 'Windows 10/11 PC'),
    ('windows nt 6.3',         'computer', 'Windows 8.1 PC'),
    ('windows nt 6.1',         'computer', 'Windows 7 PC'),
    ('windows nt',             'computer', 'Windows PC'),
    ('iphone',                 'mobile',   'iPhone'),
    ('ipad',                   'mobile',   'iPad'),
    ('android',                'mobile',   'Android Device'),
    ('macintosh; intel mac',   'computer', 'Mac Computer'),
    ('macintosh',              'computer', 'Mac Computer'),
    ('cros',                   'computer', 'Chromebook'),
    ('linux x86_64',           'computer', 'Linux PC'),
    ('linux',                  'computer', 'Linux Host'),
    ('curl/',                  'server',   'Script (curl)'),
    ('python-requests',        'server',   'Python Script'),
    ('python/',                'server',   'Python Script'),
    ('wget/',                  'server',   'Wget Script'),
    ('go-http-client',         'server',   'Go Application'),
    ('java/',                  'server',   'Java Application'),
    ('okhttp',                 'mobile',   'Android App'),
    ('cfnetwork',              'mobile',   'iOS / macOS App'),
    ('dalvik',                 'mobile',   'Android App'),
    ('mozilla/',               'computer', 'Browser'),
]

# OUI manufacturer keyword → (device_type, human_label)
_OUI_DEVICE_HINTS: dict[str, tuple[str, str]] = {
    'VMware':          ('computer', 'Virtual Machine (VMware)'),
    'VirtualBox':      ('computer', 'Virtual Machine (VirtualBox)'),
    'QEMU/KVM':        ('computer', 'Virtual Machine (KVM)'),
    'Hyper-V':         ('computer', 'Virtual Machine (Hyper-V)'),
    'Raspberry Pi':    ('iot',      'Raspberry Pi'),
    'Cisco':           ('switch',   'Cisco Network Device'),
    'Juniper':         ('switch',   'Juniper Network Device'),
    'Netgear':         ('gateway',  'Netgear Router/Switch'),
    'TP-Link':         ('gateway',  'TP-Link Router/Switch'),
    'ASUS':            ('gateway',  'ASUS Router'),
    'Super Micro':     ('server',   'Supermicro Server'),
    'Intel':           ('computer', 'Intel-based Device'),
    'Dell':            ('computer', 'Dell Device'),
    'Realtek':         ('computer', 'Realtek-based Device'),
}

# Compact OUI prefix table (first 3 octets, uppercase, colon-separated)
_OUI: dict[str, str] = {
    '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:15:5D': 'Microsoft Hyper-V',
    '52:54:00': 'QEMU/KVM', '08:00:27': 'VirtualBox',
    '00:1A:A0': 'Dell', '00:14:22': 'Dell', '14:18:77': 'Dell',
    'B8:27:EB': 'Raspberry Pi', 'DC:A6:32': 'Raspberry Pi', 'E4:5F:01': 'Raspberry Pi',
    '00:E0:4C': 'Realtek', '00:1B:21': 'Intel', '8C:EC:4B': 'Intel',
    'F4:4D:30': 'Intel', '00:1C:C0': 'Intel', '88:AE:1D': 'Intel',
    '00:25:90': 'Super Micro', 'AC:1F:6B': 'Super Micro',
    '00:0A:F7': 'Cisco', '00:17:94': 'Cisco', '00:1A:2F': 'Cisco',
    'FC:FB:FB': 'Juniper', '00:90:69': 'Juniper',
    'F8:DB:88': 'TP-Link', '50:C7:BF': 'TP-Link',
    'C4:6E:1F': 'ASUS', '10:7B:44': 'ASUS',
    'E0:CB:4E': 'Netgear', '20:E5:2A': 'Netgear',
}


def _mac_str(mac_bytes: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in mac_bytes)


def _oui_lookup(mac: str) -> str:
    return _OUI.get(mac[:8].upper(), '')


def _ts_str(ts: float) -> str:
    return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def _ip_to_subnet(ip: str) -> str:
    """Return the /24 CIDR block for an IP, e.g. '192.168.1.0/24'."""
    try:
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass
    return 'unknown'


class DiscoveryAnalyzer:
    """
    Passive asset identification + MITM detection.

    Tracks Layer-2 / ARP state to identify the network gateway and detect
    Man-in-the-Middle attacks, and fingerprints each device to assign a
    type (computer, mobile, IoT, printer, server, switch, gateway).
    """

    def __init__(self) -> None:
        # ARP tracking
        self._arp_log: dict[str, list] = defaultdict(list)       # ip → [(ts, mac), ...]
        self._mac_ips: dict[str, set]  = defaultdict(set)        # mac → set of IPs
        self._grat_arps: list[dict]    = []

        # DNS / name-service
        self._dns_obs: dict[str, list]       = defaultdict(list)  # domain → [(ts, src_ip, resolved_ip)]
        self._name_responses: dict[str, set] = defaultdict(set)   # ip → set of names

        # Device fingerprinting
        self._mdns_services: dict[str, set] = defaultdict(set)   # ip → service type strings
        self._ssdp_devices: dict[str, dict] = defaultdict(dict)  # ip → SSDP headers
        self._lldp_macs: set[str]           = set()              # MACs of LLDP-speaking devices
        self._ua_hints: dict[str, str]      = {}                  # ip → best User-Agent string
        self._dhcp_servers: set[str]        = set()              # IPs confirmed as DHCP servers
        self._dhcp_mac_hints: dict[str, dict] = {}               # mac → {hostname, vendor_class}
        self._nbns_ips: set[str]            = set()              # IPs seen doing NBNS (Windows)

    # ── Public feed entry-point ───────────────────────────────────

    def feed(self, ts: float, buf: bytes, eth=None) -> None:
        try:
            if eth is None:
                eth = dpkt.ethernet.Ethernet(buf)
            etype = eth.type
            if etype == dpkt.ethernet.ETH_TYPE_ARP:
                self._feed_arp(ts, eth)
            elif etype == dpkt.ethernet.ETH_TYPE_IP:
                self._feed_ipv4(ts, eth)
            elif etype == _LLDP_ETYPE:
                self._feed_lldp(eth)
        except Exception:
            pass

    # ── Internal handlers ─────────────────────────────────────────

    def _feed_arp(self, ts: float, eth) -> None:
        try:
            arp = eth.data
            if not isinstance(arp, dpkt.arp.ARP):
                return
            if arp.pro != dpkt.arp.ARP_PRO_IP:
                return

            sender_mac = _mac_str(arp.sha)
            sender_ip  = socket.inet_ntoa(arp.spa)

            self._arp_log[sender_ip].append((ts, sender_mac))
            self._mac_ips[sender_mac].add(sender_ip)

            if arp.op == _ARP_REPLY and arp.spa == arp.tpa:
                self._grat_arps.append({'ip': sender_ip, 'mac': sender_mac, 'ts': ts})
        except Exception:
            pass

    def _feed_ipv4(self, ts: float, eth) -> None:
        try:
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                return
            udp = ip.data
            if not isinstance(udp, dpkt.udp.UDP):
                return

            src_ip = socket.inet_ntoa(ip.src)
            sport  = udp.sport
            dport  = udp.dport

            if sport == 53:
                self._feed_dns_response(ts, src_ip, udp.data)
            elif sport in (_LLMNR_PORT, _MDNS_PORT, _NBNS_PORT) or dport in (_LLMNR_PORT, _MDNS_PORT, _NBNS_PORT):
                self._feed_name_service(ts, src_ip, udp.data, sport)
            elif sport == _SSDP_PORT or dport == _SSDP_PORT:
                self._feed_ssdp(ts, src_ip, udp.data)
            elif sport == 67 or dport == 67:  # DHCP
                self._feed_dhcp(ts, src_ip, udp.data)
        except Exception:
            pass

    def _feed_dns_response(self, ts: float, src_ip: str, payload: bytes) -> None:
        try:
            dns = dpkt.dns.DNS(payload)
            if dns.qr != dpkt.dns.DNS_R or not dns.an:
                return
            for q in dns.qd:
                name = q.name.rstrip('.').lower()
                for rr in dns.an:
                    if rr.type == dpkt.dns.DNS_A:
                        resolved_ip = socket.inet_ntoa(rr.rdata)
                        self._dns_obs[name].append((ts, src_ip, resolved_ip))
        except Exception:
            pass

    def _feed_name_service(self, ts: float, src_ip: str, payload: bytes, sport: int) -> None:
        try:
            # NBNS is Windows-specific — any participant is almost certainly a Windows machine
            if sport == _NBNS_PORT:
                self._nbns_ips.add(src_ip)

            dns = dpkt.dns.DNS(payload)
            for q in dns.qd:
                name = q.name.rstrip('.').lower()
                if name:
                    self._name_responses[src_ip].add(name)
                    self._check_mdns_service(src_ip, name)
            if dns.qr == dpkt.dns.DNS_R:
                for rr in dns.an:
                    name = rr.name.rstrip('.').lower()
                    if name:
                        self._name_responses[src_ip].add(name)
                        self._check_mdns_service(src_ip, name)
        except Exception:
            pass

    def _check_mdns_service(self, src_ip: str, name: str) -> None:
        for svc_key in _MDNS_SERVICES:
            if svc_key in name:
                self._mdns_services[src_ip].add(svc_key)
                return

    def _feed_ssdp(self, ts: float, src_ip: str, payload: bytes) -> None:
        try:
            text = payload.decode('utf-8', errors='ignore')
            info: dict[str, str] = {}
            for line in text.splitlines():
                if ':' in line:
                    key, _, val = line.partition(':')
                    k = key.strip().upper()
                    if k in ('SERVER', 'NT', 'ST', 'LOCATION', 'USN'):
                        info[k] = val.strip()
            if info:
                self._ssdp_devices[src_ip].update(info)
        except Exception:
            pass

    def _feed_lldp(self, eth) -> None:
        """Record the source MAC of any LLDP frame — marks a managed switch/router."""
        try:
            src_mac = _mac_str(eth.src)
            self._lldp_macs.add(src_mac)
        except Exception:
            pass

    def _feed_dhcp(self, ts: float, src_ip: str, payload: bytes) -> None:
        try:
            if len(payload) < 240:
                return
            op = payload[0]
            if payload[236:240] != b'\x63\x82\x53\x63':  # magic cookie
                return

            # Client MAC is in chaddr field (bytes 28–33)
            client_mac = ':'.join(f'{b:02x}' for b in payload[28:34])

            hostname     = ''
            vendor_class = ''
            i = 240
            while i < len(payload):
                opt = payload[i]
                if opt == 255:  # END
                    break
                if opt == 0:    # PAD
                    i += 1
                    continue
                if i + 1 >= len(payload):
                    break
                length    = payload[i + 1]
                val_start = i + 2
                val_end   = val_start + length
                if val_end > len(payload):
                    break

                if opt == 12:   # Hostname
                    hostname = payload[val_start:val_end].decode('utf-8', errors='ignore').strip()
                elif opt == 60:  # Vendor Class Identifier
                    vendor_class = payload[val_start:val_end].decode('utf-8', errors='ignore').strip()
                elif opt == 53 and length >= 1 and op == 2:
                    msg_type = payload[val_start]
                    if msg_type in (2, 5):  # OFFER or ACK → confirm server
                        self._dhcp_servers.add(src_ip)

                i = val_end

            # Store client hints keyed by MAC (available on both requests and replies)
            if op == 1 and client_mac and (hostname or vendor_class):
                existing = self._dhcp_mac_hints.get(client_mac, {})
                if hostname and not existing.get('hostname'):
                    existing['hostname'] = hostname
                if vendor_class and not existing.get('vendor_class'):
                    existing['vendor_class'] = vendor_class
                self._dhcp_mac_hints[client_mac] = existing

        except Exception:
            pass

    # ── Multiprocessing state ─────────────────────────────────────

    def get_state(self) -> dict:
        return {
            'arp_log':        {ip: list(e)    for ip, e    in self._arp_log.items()},
            'mac_ips':        {mac: list(ips) for mac, ips in self._mac_ips.items()},
            'grat_arps':      list(self._grat_arps),
            'dns_obs':        {d: list(obs)   for d, obs   in self._dns_obs.items()},
            'name_responses': {ip: list(n)    for ip, n    in self._name_responses.items()},
            'mdns_services':  {ip: list(s)    for ip, s    in self._mdns_services.items()},
            'ssdp_devices':   dict(self._ssdp_devices),
            'lldp_macs':      list(self._lldp_macs),
            'ua_hints':       dict(self._ua_hints),
            'dhcp_servers':   list(self._dhcp_servers),
            'dhcp_mac_hints': dict(self._dhcp_mac_hints),
            'nbns_ips':       list(self._nbns_ips),
        }

    def merge_state(self, state: dict) -> None:
        for ip, entries in state['arp_log'].items():
            self._arp_log[ip].extend(entries)
        for mac, ips in state['mac_ips'].items():
            self._mac_ips[mac].update(ips)
        self._grat_arps.extend(state['grat_arps'])
        for domain, obs in state['dns_obs'].items():
            self._dns_obs[domain].extend(obs)
        for ip, names in state['name_responses'].items():
            self._name_responses[ip].update(names)
        for ip, svcs in state.get('mdns_services', {}).items():
            self._mdns_services[ip].update(svcs)
        for ip, info in state.get('ssdp_devices', {}).items():
            self._ssdp_devices[ip].update(info)
        self._lldp_macs.update(state.get('lldp_macs', []))
        for ip, ua in state.get('ua_hints', {}).items():
            if ip not in self._ua_hints:
                self._ua_hints[ip] = ua
        self._dhcp_servers.update(state.get('dhcp_servers', []))
        for mac, hints in state.get('dhcp_mac_hints', {}).items():
            existing = self._dhcp_mac_hints.get(mac, {})
            if hints.get('hostname') and not existing.get('hostname'):
                existing['hostname'] = hints['hostname']
            if hints.get('vendor_class') and not existing.get('vendor_class'):
                existing['vendor_class'] = hints['vendor_class']
            self._dhcp_mac_hints[mac] = existing
        self._nbns_ips.update(state.get('nbns_ips', []))

    # ── Finalize ──────────────────────────────────────────────────

    def finalize(self, http_results: dict | None = None, hosts_results: dict | None = None) -> dict:
        mac_flips   = self._detect_mac_flips()
        mac_multiip = self._detect_mac_multiip()
        grat_arps   = self._dedup_grat_arps()
        dns_races   = self._detect_dns_races()
        name_spoof  = self._detect_name_spoof()
        gateway     = self._detect_gateway()
        arp_table   = self._build_arp_table()

        # Inject UA hints from HTTP results before classifying devices
        if http_results:
            for req in http_results.get('requests', []):
                src = req.get('src', '')
                ua  = req.get('user_agent', '')
                if src and ua and src not in self._ua_hints:
                    self._ua_hints[src] = ua

        # Build DNS server set: IPs that replied to port-53 queries (internal only)
        dns_server_ips: set[str] = {
            src_ip
            for obs_list in self._dns_obs.values()
            for _, src_ip, _ in obs_list
            if is_internal(src_ip)
        }

        # Build device inventory
        devices = self._build_device_inventory(gateway, arp_table, dns_server_ips)

        # Build topology (mac_flips passed for critical-IP summary)
        topology = self._build_topology(
            gateway, arp_table, devices, http_results, dns_server_ips, hosts_results,
            mitm_alerts=[{'ip': f['ip'], 'severity': 'CRITICAL'} for f in mac_flips],
        )

        mitm_alerts: list[dict] = []
        for flip in mac_flips:
            mitm_alerts.append({
                'type': 'ARP_SPOOFING', 'severity': 'CRITICAL',
                'detail': flip['description'], 'ts': flip['ts'],
            })
        for entry in mac_multiip:
            mitm_alerts.append({
                'type': 'MAC_CLAIMING_MULTIPLE_IPS', 'severity': 'HIGH',
                'detail': entry['description'], 'ts': '',
            })
        if grat_arps:
            mitm_alerts.append({
                'type': 'GRATUITOUS_ARP', 'severity': 'MEDIUM',
                'detail': f'{len(grat_arps)} unsolicited ARP repl{"ies" if len(grat_arps) != 1 else "y"} detected',
                'ts': grat_arps[0]['ts'],
            })
        for race in dns_races:
            mitm_alerts.append({
                'type': 'DNS_CONFLICT', 'severity': 'HIGH',
                'detail': race['description'], 'ts': '',
            })
        for spoofer in name_spoof:
            mitm_alerts.append({
                'type': 'NAME_SERVICE_SPOOFING', 'severity': 'HIGH',
                'detail': spoofer['description'], 'ts': '',
            })

        return {
            'gateway':       gateway,
            'mac_flips':     mac_flips,
            'mac_multiip':   mac_multiip,
            'grat_arps':     grat_arps,
            'dns_races':     dns_races,
            'name_spoofers': name_spoof,
            'mitm_alerts':   mitm_alerts,
            'arp_table':     arp_table,
            'devices':       devices,
            'topology':      topology,
        }

    # ── Device classification ─────────────────────────────────────

    def _classify_device(self, ip: str, mac: str) -> tuple[str, str]:
        """Heuristic classification → (device_type, human_label)."""

        # 1. mDNS service types (highest confidence — device announced itself)
        for svc in self._mdns_services.get(ip, set()):
            if svc in _MDNS_SERVICES:
                return _MDNS_SERVICES[svc]

        # 2. SSDP / UPnP advertisement
        ssdp = self._ssdp_devices.get(ip, {})
        if ssdp:
            server = ssdp.get('SERVER', '').lower()
            nt     = (ssdp.get('NT') or ssdp.get('ST') or '').lower()
            if any(k in server for k in ('camera', 'axis', 'hikvision', 'dahua', 'vivotek')):
                return 'iot', 'IP Camera'
            if 'printer' in server or 'print' in nt or 'ipp' in nt:
                return 'printer', 'Network Printer'
            if any(k in server for k in ('tv', 'television', 'roku', 'firetv', 'appletv')):
                return 'iot', 'Smart TV'
            if 'router' in server or 'gateway' in server:
                return 'gateway', 'Router/Gateway'
            if 'windows' in server:
                return 'computer', 'Windows PC (UPnP)'
            return 'iot', 'UPnP Device'

        # 3. LLDP source (managed switch/router)
        if mac and mac in self._lldp_macs:
            return 'switch', 'Managed Switch / Router (LLDP)'

        # 4. OUI manufacturer
        oui_name = _oui_lookup(mac) if mac else ''
        if oui_name:
            for keyword, hint in _OUI_DEVICE_HINTS.items():
                if keyword in oui_name:
                    return hint

        # 5. DHCP vendor class identifier (option 60) — very reliable OS/device signal
        mac_hint = self._dhcp_mac_hints.get(mac, {}) if mac else {}
        vendor_class = mac_hint.get('vendor_class', '')
        if vendor_class:
            vc_lower = vendor_class.lower()
            for pattern, dtype, label in _DHCP_VENDOR_PATTERNS:
                if pattern.lower() in vc_lower:
                    return dtype, label

        # 6. HTTP User-Agent
        ua = self._ua_hints.get(ip, '').lower()
        if ua:
            for pattern, dtype, label in _UA_PATTERNS:
                if pattern in ua:
                    return dtype, label

        # 7. NBNS participation — protocol is Windows-only
        if ip in self._nbns_ips:
            return 'computer', 'Windows PC (NBNS)'

        return 'unknown', 'Unknown Device'

    # ── Device inventory ──────────────────────────────────────────

    def _build_device_inventory(self, gateway: dict | None, arp_table: list[dict], dns_server_ips: set[str] | None = None) -> list[dict]:
        gw_ip = gateway['ip'] if gateway else None
        dns_server_ips = dns_server_ips or set()
        devices: list[dict] = []

        # Start with gateway
        if gateway:
            dtype, dlabel = 'gateway', 'Gateway / Router'
            gw_roles: list[str] = []
            if gw_ip in dns_server_ips:
                gw_roles.append('DNS Server')
            if gw_ip in self._dhcp_servers:
                gw_roles.append('DHCP Server')
            devices.append({
                'ip': gw_ip, 'mac': gateway['mac'],
                'manufacturer': gateway.get('manufacturer', ''),
                'device_type': dtype, 'device_label': dlabel,
                'services': [],
                'ua': self._ua_hints.get(gw_ip, ''),
                'ssdp': bool(self._ssdp_devices.get(gw_ip)),
                'lldp': gateway['mac'] in self._lldp_macs,
                'mdns': list(self._mdns_services.get(gw_ip, set())),
                'fingerprint_source': 'gateway_heuristic',
                'is_dns_server': gw_ip in dns_server_ips,
                'is_dhcp_server': gw_ip in self._dhcp_servers,
                'roles': gw_roles,
            })

        for row in arp_table:
            ip  = row['ip']
            mac = row['mac']
            if ip == gw_ip:
                continue

            dtype, dlabel = self._classify_device(ip, mac)

            # DNS/DHCP server override
            is_dns  = ip in dns_server_ips
            is_dhcp = ip in self._dhcp_servers
            if is_dns and dtype == 'unknown':
                dtype, dlabel = 'server', 'DNS Server'
            if is_dhcp and dtype == 'unknown':
                dtype, dlabel = 'server', 'DHCP Server'

            # Determine how we fingerprinted this device
            sources: list[str] = []
            if is_dns:
                sources.append('DNS server')
            if is_dhcp:
                sources.append('DHCP server')
            if self._mdns_services.get(ip):
                sources.append('mDNS')
            if self._ssdp_devices.get(ip):
                sources.append('SSDP')
            if mac in self._lldp_macs:
                sources.append('LLDP')
            if _oui_lookup(mac):
                sources.append('OUI')
            if self._dhcp_mac_hints.get(mac, {}).get('vendor_class'):
                sources.append('DHCP vendor class')
            if self._dhcp_mac_hints.get(mac, {}).get('hostname'):
                sources.append('DHCP hostname')
            if ip in self._nbns_ips:
                sources.append('NBNS')
            if self._ua_hints.get(ip):
                sources.append('HTTP UA')
            if not sources:
                sources.append('ARP only')

            roles: list[str] = []
            if is_dns:
                roles.append('DNS Server')
            if is_dhcp:
                roles.append('DHCP Server')

            dhcp_hint = self._dhcp_mac_hints.get(mac, {})
            devices.append({
                'ip':                ip,
                'mac':               mac,
                'manufacturer':      row.get('manufacturer', ''),
                'device_type':       dtype,
                'device_label':      dlabel,
                'hostname':          dhcp_hint.get('hostname', ''),
                'vendor_class':      dhcp_hint.get('vendor_class', ''),
                'services':          list(self._mdns_services.get(ip, set())),
                'ua':                self._ua_hints.get(ip, ''),
                'ssdp':              bool(self._ssdp_devices.get(ip)),
                'lldp':              mac in self._lldp_macs,
                'mdns':              list(self._mdns_services.get(ip, set())),
                'fingerprint_source': ', '.join(sources),
                'arp_count':         row.get('arp_count', 0),
                'mac_changes':       row.get('mac_changes', 0),
                'is_dns_server':     is_dns,
                'is_dhcp_server':    is_dhcp,
                'roles':             roles,
            })

        return devices

    # ── Topology ──────────────────────────────────────────────────

    def _build_topology(
        self,
        gateway:        dict | None,
        arp_table:      list[dict],
        devices:        list[dict],
        http_results:   dict | None,
        dns_server_ips: set[str] | None = None,
        hosts_results:  dict | None = None,
        mitm_alerts:    list[dict] | None = None,
    ) -> dict:
        dns_server_ips = dns_server_ips or set()
        # IPs flagged by MITM alerts (for summary count and future ring colouring)
        critical_ips: set[str] = set()
        for alert in (mitm_alerts or []):
            if alert.get('severity') in ('CRITICAL', 'HIGH') and alert.get('ip'):
                critical_ips.add(alert['ip'])
        nodes: list[dict] = []
        edges: list[dict] = []
        seen_nodes: set[str] = set()
        seen_edges: set[tuple] = set()
        gw_ip = gateway['ip'] if gateway else None

        # Packet-count lookup and DC candidate from hosts data
        host_packet_map: dict[str, int] = {}
        dc_candidate: str | None = None
        if hosts_results:
            dc_candidate = hosts_results.get('dc_candidate')
            for h in hosts_results.get('hosts', []):
                hip = h.get('ip', '')
                if hip:
                    host_packet_map[hip] = h.get('packet_count', 0)

        # Track how many directed edges arrive at each external node
        ext_conn_counts: dict[str, int] = {}

        def add_node(nid: str, label: str, ntype: str, **kw) -> None:
            if nid not in seen_nodes:
                seen_nodes.add(nid)
                nodes.append({'id': nid, 'label': label, 'type': ntype, **kw})

        def add_edge(from_id: str, to_id: str, proto: str, label: str = '') -> None:
            k = (from_id, to_id, proto)
            if k not in seen_edges:
                seen_edges.add(k)
                edges.append({'from': from_id, 'to': to_id, 'proto': proto, 'label': label})
                if to_id.startswith('ext:'):
                    ext_conn_counts[to_id] = ext_conn_counts.get(to_id, 0) + 1

        # Identify shadow IoT (IoT/printer devices making external HTTP contacts)
        shadow_iot_ips: set[str] = set()
        shadow_iot_contacts: list[dict] = []
        if http_results:
            ip_to_type = {d['ip']: d['device_type'] for d in devices}
            seen_shadow: set[tuple] = set()
            for req in http_results.get('requests', []):
                src  = req.get('src', '')
                host = req.get('host', '')
                if not src or not host or is_internal(host):
                    continue
                dtype = ip_to_type.get(src, 'unknown')
                if dtype not in ('iot', 'printer'):
                    continue
                k = (src, host)
                if k not in seen_shadow:
                    seen_shadow.add(k)
                    shadow_iot_ips.add(src)
                    shadow_iot_contacts.append({
                        'ip': src, 'host': host, 'severity': 'HIGH',
                        'description': f'IoT/printer {src} contacted external host {host}',
                    })

        # Add all internal device nodes
        for dev in devices:
            ip    = dev['ip']
            dtype = dev['device_type']
            roles = list(dev.get('roles', []))
            is_dc = (ip == dc_candidate)
            if is_dc and 'DC Candidate' not in roles:
                roles.append('DC Candidate')
            role_suffix = f"\n[{', '.join(roles)}]" if roles else ''
            label     = f"{dev['device_label']}\n{ip}{role_suffix}"
            pkt_count = host_packet_map.get(ip, 0)
            fp_src    = dev.get('fingerprint_source', '')
            tooltip = (
                f"MAC: {dev['mac']}\n"
                f"Manufacturer: {dev.get('manufacturer') or '—'}\n"
                f"Type: {dev['device_label']}\n"
                f"Packets: {pkt_count:,}\n"
                f"Fingerprinted via: {fp_src or '—'}"
            )
            if dev.get('hostname'):
                tooltip += f"\nHostname: {dev['hostname']}"
            if dev.get('vendor_class'):
                tooltip += f"\nDHCP vendor: {dev['vendor_class']}"
            if roles:
                tooltip += f"\nRoles: {', '.join(roles)}"
            if dev.get('ua'):
                tooltip += f"\nUA: {dev['ua'][:60]}"
            if dev.get('services'):
                tooltip += f"\nmDNS: {', '.join(dev['services'][:3])}"

            add_node(ip, label, dtype,
                     mac=dev['mac'],
                     manufacturer=dev.get('manufacturer', ''),
                     shadow_iot=ip in shadow_iot_ips,
                     is_dns_server=dev.get('is_dns_server', False),
                     is_dhcp_server=dev.get('is_dhcp_server', False),
                     is_dc_candidate=is_dc,
                     packet_count=pkt_count,
                     fingerprinted=bool(fp_src and fp_src != 'ARP only'),
                     subnet=_ip_to_subnet(ip),
                     tooltip=tooltip)

            # Internal → Gateway edge
            if gw_ip and ip != gw_ip:
                add_edge(ip, gw_ip, 'arp')

        # LLDP-identified devices not already in ARP table
        mac_to_ip = {row['mac']: row['ip'] for row in arp_table}
        for lldp_mac in self._lldp_macs:
            lldp_ip = mac_to_ip.get(lldp_mac)
            if lldp_ip:
                continue  # already in devices list
            nid = f'lldp:{lldp_mac}'
            add_node(nid, f"Switch\n{lldp_mac}", 'switch',
                     mac=lldp_mac,
                     manufacturer=_oui_lookup(lldp_mac),
                     shadow_iot=False,
                     is_dc_candidate=False,
                     packet_count=0,
                     fingerprinted=True,
                     subnet='unknown',
                     tooltip=f"MAC: {lldp_mac}\nLLDP-identified managed device")
            if gw_ip:
                add_edge(nid, gw_ip, 'lldp')

        # Any IP seen in packet flows but missing from ARP/device inventory
        if hosts_results:
            for h in hosts_results.get('hosts', []):
                hip = h.get('ip', '')
                if not hip or hip in seen_nodes:
                    continue
                pkt_count = h.get('packet_count', 0)
                if is_internal(hip):
                    dtype, dlabel = self._classify_device(hip, '')
                    is_dns  = hip in dns_server_ips
                    is_dhcp = hip in self._dhcp_servers
                    is_dc   = (hip == dc_candidate)
                    if is_dns and dtype == 'unknown':
                        dtype, dlabel = 'server', 'DNS Server'
                    if is_dhcp and dtype == 'unknown':
                        dtype, dlabel = 'server', 'DHCP Server'
                    roles = []
                    if is_dns:  roles.append('DNS Server')
                    if is_dhcp: roles.append('DHCP Server')
                    if is_dc:   roles.append('DC Candidate')
                    role_suffix = f"\n[{', '.join(roles)}]" if roles else ''
                    label   = f"{dlabel}\n{hip}{role_suffix}"
                    tooltip = (
                        f"IP: {hip}\nMAC: —\n"
                        f"Packets: {pkt_count:,}\n"
                        f"Source: flow traffic only (no ARP seen)"
                    )
                    if roles:
                        tooltip += f"\nRoles: {', '.join(roles)}"
                    add_node(hip, label, dtype,
                             mac='', manufacturer='',
                             shadow_iot=False,
                             is_dns_server=is_dns,
                             is_dhcp_server=is_dhcp,
                             is_dc_candidate=is_dc,
                             packet_count=pkt_count,
                             fingerprinted=False,
                             subnet=_ip_to_subnet(hip),
                             tooltip=tooltip)
                    if gw_ip and hip != gw_ip:
                        add_edge(hip, gw_ip, 'arp')
                else:
                    ext_id = f'ext:{hip}'
                    if ext_id not in seen_nodes:
                        add_node(ext_id, hip, 'external',
                                 mac='', manufacturer='',
                                 shadow_iot=False,
                                 is_dc_candidate=False,
                                 packet_count=pkt_count,
                                 fingerprinted=False,
                                 connection_count=0,
                                 subnet='external',
                                 tooltip=f"External IP: {hip}\nPackets: {pkt_count:,}")

        # External nodes from HTTP requests (cap at 50)
        if http_results:
            ext_count = 0
            req_list = http_results.get('flagged_requests', []) + http_results.get('requests', [])
            seen_ext: set[str] = set()
            for req in req_list:
                src  = req.get('src', '')
                host = req.get('host', '')
                if not host or is_internal(host):
                    continue
                ext_id = f'ext:{host}'
                if ext_id not in seen_ext:
                    if ext_count >= 50:
                        continue
                    seen_ext.add(ext_id)
                    ext_count += 1
                    add_node(ext_id, host, 'external',
                             mac='', manufacturer='',
                             shadow_iot=False,
                             is_dc_candidate=False,
                             packet_count=0,
                             fingerprinted=False,
                             connection_count=0,
                             subnet='external',
                             tooltip=f"External host: {host}")
                if src in seen_nodes:
                    proto = 'https' if '443' in req.get('url', '') else 'http'
                    add_edge(src, ext_id, proto, proto.upper())

        # Patch external nodes with final connection counts + request-count labels
        for node in nodes:
            if node['type'] == 'external':
                count = ext_conn_counts.get(node['id'], 0)
                node['connection_count'] = count
                if count > 0:
                    base = node['label'].split('\n(')[0]
                    node['label'] = f"{base}\n({count} req)"
                    node['tooltip'] = node.get('tooltip', '') + f"\nConnections seen: {count}"

        # Build summary counts for the stats bar
        internal_nodes = [n for n in nodes if n['type'] != 'external']
        external_nodes = [n for n in nodes if n['type'] == 'external']
        subnet_set     = {n['subnet'] for n in internal_nodes if n.get('subnet') not in ('unknown', None)}
        shadow_ips_set = {c['ip'] for c in shadow_iot_contacts}
        summary = {
            'total_internal':   len(internal_nodes),
            'total_external':   len(external_nodes),
            'subnet_count':     len(subnet_set),
            'gateway_count':    len([n for n in nodes if n['type'] == 'gateway']),
            'critical_count':   len(critical_ips),
            'shadow_iot_count': len(shadow_ips_set),
        }

        return {
            'nodes':       nodes,
            'edges':       edges,
            'shadow_iot':  shadow_iot_contacts[:20],
            'summary':     summary,
        }

    # ── Detection helpers ─────────────────────────────────────────

    def _detect_mac_flips(self) -> list[dict]:
        flips: list[dict] = []
        for ip, entries in self._arp_log.items():
            sorted_entries = sorted(entries, key=lambda x: x[0])
            current_mac: str | None = None
            for ts, mac in sorted_entries:
                if current_mac is None:
                    current_mac = mac
                elif mac != current_mac:
                    flips.append({
                        'ip':          ip,
                        'old_mac':     current_mac,
                        'new_mac':     mac,
                        'ts':          _ts_str(ts),
                        'severity':    'CRITICAL',
                        'description': (
                            f'IP {ip} changed MAC from {current_mac} '
                            f'({_oui_lookup(current_mac) or "unknown"}) '
                            f'to {mac} ({_oui_lookup(mac) or "unknown"})'
                        ),
                    })
                    current_mac = mac
        return flips

    def _detect_mac_multiip(self) -> list[dict]:
        results = []
        for mac, ips in self._mac_ips.items():
            if len(ips) >= 4:
                results.append({
                    'mac':         mac,
                    'ips':         sorted(ips),
                    'count':       len(ips),
                    'severity':    'HIGH',
                    'description': f'MAC {mac} claimed {len(ips)} different IPs',
                })
        return results

    def _dedup_grat_arps(self) -> list[dict]:
        seen: set = set()
        deduped: list[dict] = []
        for g in self._grat_arps:
            k = (g['ip'], g['mac'])
            if k not in seen:
                seen.add(k)
                deduped.append({'ip': g['ip'], 'mac': g['mac'], 'ts': _ts_str(g['ts'])})
        return deduped

    def _detect_dns_races(self) -> list[dict]:
        races: list[dict] = []
        for domain, obs in self._dns_obs.items():
            server_answers: dict[str, set] = defaultdict(set)
            for _ts, src_ip, resolved_ip in obs:
                server_answers[src_ip].add(resolved_ip)
            if len(server_answers) < 2:
                continue
            all_resolved: set[str] = set()
            for ips in server_answers.values():
                all_resolved.update(ips)
            if len(all_resolved) < 2:
                continue
            races.append({
                'domain':      domain,
                'servers':     {srv: sorted(ans) for srv, ans in server_answers.items()},
                'severity':    'HIGH',
                'description': (
                    f'DNS conflict for "{domain}": {len(server_answers)} servers '
                    f'returned different answers ({", ".join(sorted(all_resolved)[:3])})'
                ),
            })
        return races

    def _detect_name_spoof(self) -> list[dict]:
        spoofers: list[dict] = []
        for ip, names in self._name_responses.items():
            if len(names) >= 5 and is_internal(ip):
                spoofers.append({
                    'ip':           ip,
                    'name_count':   len(names),
                    'sample_names': sorted(names)[:5],
                    'severity':     'HIGH',
                    'description':  (
                        f'{ip} responded to {len(names)} unique name-resolution queries '
                        f'(possible LLMNR/mDNS/NBNS spoofing)'
                    ),
                })
        return spoofers

    def _detect_gateway(self) -> dict | None:
        candidates: dict[str, int] = {}
        for ip, entries in self._arp_log.items():
            if not is_internal(ip):
                continue
            last_octet = ip.rsplit('.', 1)[-1]
            if last_octet in ('1', '254'):
                candidates[ip] = candidates.get(ip, 0) + len(entries)
        if not candidates:
            return None

        gateway_ip  = max(candidates, key=lambda ip: candidates[ip])
        entries     = sorted(self._arp_log.get(gateway_ip, []), key=lambda x: x[0])
        gateway_mac = entries[-1][1] if entries else 'unknown'

        return {
            'ip':           gateway_ip,
            'mac':          gateway_mac,
            'manufacturer': _oui_lookup(gateway_mac),
        }

    def _build_arp_table(self) -> list[dict]:
        table: list[dict] = []
        for ip, entries in self._arp_log.items():
            if not entries:
                continue
            sorted_e    = sorted(entries, key=lambda x: x[0])
            latest_mac  = sorted_e[-1][1]
            unique_macs = len({mac for _, mac in sorted_e})
            table.append({
                'ip':           ip,
                'mac':          latest_mac,
                'manufacturer': _oui_lookup(latest_mac),
                'arp_count':    len(entries),
                'mac_changes':  unique_macs - 1,
            })
        table.sort(key=lambda x: x['arp_count'], reverse=True)
        return table[:60]
