import socket
import concurrent.futures
import ssl
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


# ── Service classification ─────────────────────────────────────────
class ServiceType(Enum):
    HTTPS           = "HTTPS"
    HTTP            = "HTTP"
    OPENVPN         = "OpenVPN"
    IPSEC           = "IPSec/IKEv2"
    WIREGUARD       = "WireGuard"
    SSL_VPN         = "SSL-VPN"
    SMTPS           = "SMTPS"
    IMAPS           = "IMAPS"
    LDAPS           = "LDAPS"
    UNKNOWN_TLS     = "Unknown-TLS"
    UNKNOWN         = "Unknown"


# ── Every port scanner ───────────────────────────
# Format: port → (service_type, protocol, is_vpn, tls_capable)
PORT_DEFINITIONS = {
    # Standard Web
    80:    (ServiceType.HTTP,       "TCP", False, False),
    443:   (ServiceType.HTTPS,      "TCP", False, True),
    8080:  (ServiceType.HTTP,       "TCP", False, False),
    8443:  (ServiceType.HTTPS,      "TCP", False, True),

    # VPN Ports ← HNDL HIGH PRIORITY targets
    1194:  (ServiceType.OPENVPN,    "TCP", True,  True),
    1194:  (ServiceType.OPENVPN,    "UDP", True,  True),
    500:   (ServiceType.IPSEC,      "UDP", True,  False),
    4500:  (ServiceType.IPSEC,      "UDP", True,  False),
    51820: (ServiceType.WIREGUARD,  "UDP", True,  False),
    10443: (ServiceType.SSL_VPN,    "TCP", True,  True),
    8888:  (ServiceType.SSL_VPN,    "TCP", True,  True),

    # Mail (often forgotten — carries sensitive data)
    465:   (ServiceType.SMTPS,      "TCP", False, True),
    993:   (ServiceType.IMAPS,      "TCP", False, True),
    995:   (ServiceType.IMAPS,      "TCP", False, True),

    # Directory / Auth
    636:   (ServiceType.LDAPS,      "TCP", False, True),
}

# ── HNDL Risk Multiplier per service ──────────────────────────────
# VPN tunnels carry persistent long-lived traffic = prime harvest target
HNDL_MULTIPLIER = {
    ServiceType.OPENVPN:  2.0,   # Highest — long-lived tunnel
    ServiceType.IPSEC:    2.0,   # Highest — long-lived tunnel
    ServiceType.SSL_VPN:  1.8,   # Very high
    ServiceType.WIREGUARD:1.5,   # High — modern but not PQC
    ServiceType.IMAPS:    1.4,   # Emails persist for years
    ServiceType.SMTPS:    1.3,
    ServiceType.LDAPS:    1.6,   # Auth data = very sensitive
    ServiceType.HTTPS:    1.0,   # Baseline
    ServiceType.HTTP:     1.0,
}

@dataclass
class PortResult:
    host: str
    port: int
    protocol: str               # TCP or UDP
    is_open: bool
    service_type: ServiceType
    is_vpn: bool
    tls_capable: bool
    hndl_multiplier: float
    banner: Optional[str] = None
    tls_supported: Optional[bool] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "is_open": self.is_open,
            "service": self.service_type.value,
            "is_vpn": self.is_vpn,
            "tls_capable": self.tls_capable,
            "tls_confirmed": self.tls_supported,
            "hndl_multiplier": self.hndl_multiplier,
            "banner": self.banner,
            "node_label": self._get_node_label()
        }

    def _get_node_label(self) -> str:
        """
        Label for your graph node — shown in the visual output
        """
        if self.is_vpn:
            return f"🔒 VPN [{self.service_type.value}] ← HNDL TARGET"
        elif self.tls_capable:
            return f"🌐 TLS [{self.service_type.value}]"
        else:
            return f"⚠️  PLAIN [{self.service_type.value}] ← No Encryption"

# ══════════════════════════════════════════════════════════════════
# BELOW IS CORE SCANNER FUNCTIONS
# ══════════════════════════════════════════════════════════════════

def probe_tcp_port(host: str, port: int, timeout: float = 3.0) -> tuple[bool, Optional[str]]:
    """
    Tries to open a raw TCP connection.
    Returns (is_open, banner_if_any)
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(2.0)
            try:
                # Some services send a banner immediately
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            except:
                banner = None
            return True, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, None


def probe_udp_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """
    UDP probe — sends empty datagram, listens for response or ICMP.
    UDP is harder — open ports often don't respond, closed ones send ICMP.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"\x00" * 16, (host, port))
            try:
                sock.recv(1024)
                return True  # Got a response — port is open
            except socket.timeout:
                # Timeout = possibly open (no ICMP unreachable received)
                return True
    except OSError:
        return False  # ICMP unreachable = port closed


def confirm_tls(host: str, port: int) -> bool:
    """
    For a port that's open — confirm it actually speaks TLS.
    Some services run on non-standard ports.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Just checking TLS exists

        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except:
        return False


def scan_single_port(host: str, port: int) -> PortResult:
    """
    Full scan of one port:
    1. Check if open
    2. Identify service type
    3. Confirm TLS if applicable
    4. Assign HNDL multiplier
    """
    definition = PORT_DEFINITIONS.get(
        port,
        (ServiceType.UNKNOWN, "TCP", False, False)
    )
    service_type, proto, is_vpn, tls_capable = definition

    # ── UDP ports (VPN) need different probe ──────────────────────
    if proto == "UDP":
        is_open = probe_udp_port(host, port)
        banner = None
    else:
        is_open, banner = probe_tcp_port(host, port)

    if not is_open:
        return PortResult(
            host=host, port=port, protocol=proto,
            is_open=False, service_type=service_type,
            is_vpn=is_vpn, tls_capable=tls_capable,
            hndl_multiplier=1.0
        )

    # ── Confirm TLS actually works on this port ───────────────────
    tls_confirmed = None
    if tls_capable and proto == "TCP":
        tls_confirmed = confirm_tls(host, port)

    hndl_mult = HNDL_MULTIPLIER.get(service_type, 1.0)

    return PortResult(
        host=host,
        port=port,
        protocol=proto,
        is_open=True,
        service_type=service_type,
        is_vpn=is_vpn,
        tls_capable=tls_capable,
        tls_supported=tls_confirmed,
        hndl_multiplier=hndl_mult,
        banner=banner
    )


def scan_all_ports(host: str, max_workers: int = 20) -> list[PortResult]:
    """
    Scans ALL ports in your definition map CONCURRENTLY.
    Uses ThreadPoolExecutor — this is your parallelism layer.

    Why concurrent? Sequential scan of 15 ports × 3s timeout = 45s per host
    Concurrent scan of 15 ports              = ~3s per host
    """
    ports_to_scan = list(PORT_DEFINITIONS.keys())

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all port scans simultaneously
        future_to_port = {
            executor.submit(scan_single_port, host, port): port
            for port in ports_to_scan
        }

        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result.is_open:          # Only keep open ports
                results.append(result)

    # Sort by HNDL risk multiplier — VPN ports float to top
    results.sort(key=lambda x: x.hndl_multiplier, reverse=True)
    return results


def get_tls_ports(scan_results: list[PortResult]) -> list[PortResult]:
    """
    Filter: only return ports where TLS certificate extraction makes sense.
    These get passed to your cert_extractor from Step 1.
    """
    return [r for r in scan_results if r.tls_capable and r.is_open]


def get_vpn_nodes(scan_results: list[PortResult]) -> list[PortResult]:
    """
    Filter: only return VPN endpoints.
    These get the HNDL warning label in your CBOM.
    """
    return [r for r in scan_results if r.is_vpn and r.is_open]
