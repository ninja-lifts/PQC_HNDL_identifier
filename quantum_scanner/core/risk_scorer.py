"""
Step 4: Risk Scorer + Label Engine
====================================
Takes raw cert + port data → outputs:
  - Quantum Risk Score (0-100)
  - Label (VULNERABLE / TRANSITIONING / SAFE)
  - PQC Certificate (if earned)
  - Remediation playbook
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from enum import Enum


# ══════════════════════════════════════════════════════════════════
# QUANTUM LABEL TIERS
# ══════════════════════════════════════════════════════════════════

class QuantumLabel(Enum):
    FULLY_QUANTUM_SAFE   = "Fully Quantum Safe"       # 🟢 Score 0-20
    QUANTUM_TRANSITIONING = "Quantum Transitioning"   # 🟡 Score 21-59
    QUANTUM_VULNERABLE   = "Quantum Vulnerable"        # 🔴 Score 60-100


# ══════════════════════════════════════════════════════════════════
# ALGORITHM RISK TABLES
# These are the core of your scoring — memorize these for judges
# ══════════════════════════════════════════════════════════════════

# Key Exchange algorithms — how session keys are established
KEY_EXCHANGE_SCORES = {
    # ── Quantum SAFE (NIST FIPS 203) ──────────────────────────────
    "ML-KEM-512":          0,    # NIST FIPS 203 — Kyber512
    "ML-KEM-768":          0,    # NIST FIPS 203 — Kyber768
    "ML-KEM-1024":         0,    # NIST FIPS 203 — Kyber1024
    "CRYSTALS-Kyber":      0,    # Older name, same algorithm
    "X25519MLKEM768":      5,    # Hybrid: X25519 + Kyber (transitional)
    "P256MLKEM768":        5,    # Hybrid: P256 + Kyber (transitional)

    # ── Transitioning ─────────────────────────────────────────────
    "X25519":             45,    # Modern classical — not PQC but safe today
    "X448":               40,    # Stronger classical — not PQC

    # ── Quantum VULNERABLE (broken by Shor's algorithm) ───────────
    "ECDHE":              75,    # Elliptic Curve Diffie-Hellman
    "ECDH":               75,
    "DHE":                70,    # Finite field Diffie-Hellman
    "DH":                 80,    # Static DH — worse than DHE
    "RSA":                90,    # RSA key exchange — critically broken
    "UNKNOWN":            60,    # Can't identify = assume vulnerable
}

# Signature / Authentication algorithms
SIGNATURE_SCORES = {
    # ── Quantum SAFE (NIST FIPS 204/205) ──────────────────────────
    "ML-DSA-44":           0,    # NIST FIPS 204 — Dilithium2
    "ML-DSA-65":           0,    # NIST FIPS 204 — Dilithium3
    "ML-DSA-87":           0,    # NIST FIPS 204 — Dilithium5
    "SLH-DSA":             0,    # NIST FIPS 205 — SPHINCS+
    "CRYSTALS-Dilithium":  0,    # Older name
    "FALCON-512":          0,    # NIST alternate — lattice-based
    "FALCON-1024":         0,

    # ── Transitioning ─────────────────────────────────────────────
    "Ed25519":            35,    # Modern classical — not PQC
    "Ed448":              30,

    # ── Quantum VULNERABLE ────────────────────────────────────────
    "RSA":                85,    # sha256WithRSAEncryption etc
    "ECDSA":              75,    # Elliptic Curve signatures
    "DSA":                90,    # Oldest — critically weak
    "sha256_with_rsa_encryption": 85,
    "sha384_with_rsa_encryption": 80,
    "ecdsa_with_sha256":  75,
    "ecdsa_with_sha384":  70,
    "UNKNOWN":            60,
}

# TLS version scores
TLS_VERSION_SCORES = {
    "TLSv1.3":    10,    # Best classical — still not PQC
    "TLSv1.2":    40,    # Acceptable but weak cipher suites possible
    "TLSv1.1":    80,    # Deprecated — should not be in production
    "TLSv1.0":    95,    # Critically deprecated
    "SSLv3":     100,    # Dead — exploitable
    "SSLv2":     100,    # Dead
    "UNKNOWN":    50,
}

# Key size penalties — bigger is safer but still not quantum safe
KEY_SIZE_PENALTIES = {
    # RSA
    "RSA": {
        512:   40,   # Critically small
        1024:  30,   # Very weak
        2048:  15,   # Standard but quantum broken
        4096:  5,    # Bigger but still quantum broken
        8192:  2,
    },
    # EC
    "EC": {
        256:   10,   # P-256 / secp256r1
        384:   7,    # P-384
        521:   4,    # P-521
    }
}

# NIST PQC approved algorithms — auto-qualifies for label
NIST_PQC_ALGORITHMS = {
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",     # FIPS 203
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",          # FIPS 204
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s",      # FIPS 205
    "CRYSTALS-Kyber", "CRYSTALS-Dilithium",          # Alt names
    "FALCON-512", "FALCON-1024",                     # NIST alt
    "X25519MLKEM768", "P256MLKEM768",                # Hybrid (transitional)
}

# Remediation mapping — what to replace with what
REMEDIATION_MAP = {
    "RSA_KEY_EXCHANGE":   "Replace RSA key exchange with ML-KEM-768 (CRYSTALS-Kyber). NIST FIPS 203.",
    "ECDHE":              "Replace ECDHE with X25519MLKEM768 hybrid as interim, then migrate to pure ML-KEM-768.",
    "DHE":                "Replace DHE with ML-KEM-768. Finite field DH is broken by Shor's algorithm.",
    "RSA_SIGNATURE":      "Replace RSA signatures with ML-DSA-65 (CRYSTALS-Dilithium). NIST FIPS 204.",
    "ECDSA":              "Replace ECDSA with ML-DSA-65 or FALCON-512. Both NIST approved.",
    "TLS_1_0":            "Immediately disable TLS 1.0. Upgrade to TLS 1.3 with PQC hybrid cipher suites.",
    "TLS_1_1":            "Disable TLS 1.1. Upgrade to TLS 1.3 with PQC hybrid cipher suites.",
    "TLS_1_2":            "Upgrade from TLS 1.2 to TLS 1.3. Enable ML-KEM hybrid key exchange groups.",
    "SMALL_KEY":          "Increase key size as interim step. Long-term: migrate to PQC algorithms.",
    "VPN_OPENVPN":        "Upgrade OpenVPN to use ML-KEM for key exchange. OpenVPN 2.6+ supports this.",
    "VPN_IPSEC":          "Upgrade IKEv2 to use ML-KEM (RFC 9370). Enable PQC-KEM additional key exchange.",
    "VPN_WIREGUARD":      "WireGuard PQC extension available. Use mceliece or kyber post-quantum handshake.",
    "EXPIRED_CERT":       "Certificate is expired. Renew immediately with PQC-signed certificate.",
    "EXPIRING_SOON":      "Certificate expiring soon. Renew with ML-DSA signed certificate.",
}


# ══════════════════════════════════════════════════════════════════
# SCORE RESULT DATA STRUCTURE
# ══════════════════════════════════════════════════════════════════

@dataclass
class RiskScore:
    # Identity
    host: str
    port: int
    service: str

    # Raw scores per component
    key_exchange_score:  float = 0.0
    signature_score:     float = 0.0
    tls_version_score:   float = 0.0
    key_size_penalty:    float = 0.0
    hndl_multiplier:     float = 1.0
    cert_validity_score: float = 0.0

    # Final
    total_score:         float = 0.0    # 0-100
    label:               QuantumLabel = QuantumLabel.QUANTUM_VULNERABLE
    is_pqc_ready:        bool = False
    certificate_awarded: Optional[str] = None

    # Findings and actions
    findings:       list = field(default_factory=list)
    remediations:   list = field(default_factory=list)
    pqc_algorithms_detected: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "scores": {
                "key_exchange":   round(self.key_exchange_score, 1),
                "signature":      round(self.signature_score, 1),
                "tls_version":    round(self.tls_version_score, 1),
                "key_size":       round(self.key_size_penalty, 1),
                "cert_validity":  round(self.cert_validity_score, 1),
            },
            "total_risk_score":       round(self.total_score, 1),
            "label":                  self.label.value,
            "is_pqc_ready":           self.is_pqc_ready,
            "certificate_awarded":    self.certificate_awarded,
            "pqc_algorithms_detected":self.pqc_algorithms_detected,
            "findings":               self.findings,
            "remediations":           self.remediations,
        }


# ══════════════════════════════════════════════════════════════════
# CORE SCORING ENGINE
# ══════════════════════════════════════════════════════════════════

def score_key_exchange(cipher_suite: str) -> tuple[float, list, list]:
    """
    Parse cipher suite string and score the key exchange component.
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        ^^^^^  ← this part is key exchange
    """
    if not cipher_suite:
        return 60.0, ["Key exchange unknown — could not parse cipher suite"], [REMEDIATION_MAP["RSA_KEY_EXCHANGE"]]

    cipher_upper = cipher_suite.upper()
    findings = []
    remediations = []
    score = 60.0  # default unknown

    # Check for PQC first
    for algo, s in KEY_EXCHANGE_SCORES.items():
        if algo.upper() in cipher_upper:
            score = s
            if s == 0:
                findings.append(f"✅ PQC key exchange detected: {algo}")
            elif s <= 10:
                findings.append(f"🟡 Hybrid PQC key exchange: {algo} — transitional, good step")
            elif s <= 45:
                findings.append(f"🟡 Modern classical key exchange: {algo} — not PQC but safer")
            else:
                findings.append(f"🔴 Quantum-vulnerable key exchange: {algo} — broken by Shor's algorithm")
                if "RSA" in algo.upper():
                    remediations.append(REMEDIATION_MAP["RSA_KEY_EXCHANGE"])
                elif "ECDHE" in algo.upper() or "ECDH" in algo.upper():
                    remediations.append(REMEDIATION_MAP["ECDHE"])
                elif "DHE" in algo.upper() or "DH" in algo.upper():
                    remediations.append(REMEDIATION_MAP["DHE"])
            return score, findings, remediations

    return score, ["Key exchange algorithm not recognized"], [REMEDIATION_MAP["RSA_KEY_EXCHANGE"]]


def score_signature(sig_algorithm: str, key_algorithm: str) -> tuple[float, list, list]:
    """
    Score the digital signature algorithm used in the certificate.
    This is the algorithm used to SIGN the cert — separate from key exchange.
    """
    findings = []
    remediations = []

    combined = f"{sig_algorithm} {key_algorithm}".upper()
    score = 60.0

    for algo, s in SIGNATURE_SCORES.items():
        if algo.upper() in combined:
            score = s
            if s == 0:
                findings.append(f"✅ PQC signature algorithm: {algo}")
            elif s <= 35:
                findings.append(f"🟡 Modern classical signature: {algo} — not PQC safe")
                remediations.append(REMEDIATION_MAP["ECDSA"])
            else:
                findings.append(f"🔴 Quantum-vulnerable signature: {algo}")
                if "RSA" in algo.upper():
                    remediations.append(REMEDIATION_MAP["RSA_SIGNATURE"])
                elif "ECDSA" in algo.upper() or "EC" in algo.upper():
                    remediations.append(REMEDIATION_MAP["ECDSA"])
            return score, findings, remediations

    return score, ["Signature algorithm not identified"], [REMEDIATION_MAP["RSA_SIGNATURE"]]


def score_tls_version(tls_version: str) -> tuple[float, list, list]:
    """
    Score the TLS protocol version.
    TLS 1.3 is best classical. Still not PQC without hybrid extensions.
    """
    findings = []
    remediations = []

    version = (tls_version or "UNKNOWN").upper().replace(" ", "")
    version = version.replace("TLSV", "TLS").replace("SSLV", "SSL")

    score_map = {
        "TLS1.3": (10,  "🟡 TLS 1.3 detected — good, but add ML-KEM hybrid group for PQC"),
        "TLS1.2": (40,  "🔴 TLS 1.2 — upgrade to TLS 1.3 with PQC hybrid cipher suites"),
        "TLS1.1": (80,  "🔴 TLS 1.1 — deprecated since 2021, immediately disable"),
        "TLS1.0": (95,  "🔴 TLS 1.0 — critically deprecated, disable immediately"),
        "SSL3":   (100, "🔴 SSLv3 — dead protocol, critical vulnerability"),
        "SSL2":   (100, "🔴 SSLv2 — dead protocol, critical vulnerability"),
    }

    for ver_key, (s, msg) in score_map.items():
        if ver_key in version:
            remediation_key = f"TLS_{ver_key.replace('TLS', '').replace('.', '_')}"
            remediations.append(REMEDIATION_MAP.get(remediation_key, REMEDIATION_MAP["TLS_1_2"]))
            return s, [msg], remediations

    return 50, ["TLS version not detected"], [REMEDIATION_MAP["TLS_1_2"]]


def score_key_size(key_algorithm: str, key_size) -> tuple[float, list, list]:
    """
    Larger keys are safer against classical attacks — but ALL RSA/EC
    keys regardless of size are broken by quantum computers.
    We still penalize small keys as they're weak even today.
    """
    findings = []
    remediations = []

    if not key_size or key_size == "Unknown":
        return 10.0, [], []

    try:
        size = int(key_size)
    except (ValueError, TypeError):
        return 10.0, [], []

    algo_upper = str(key_algorithm).upper()

    if "RSA" in algo_upper:
        if size < 2048:
            findings.append(f"🔴 RSA-{size} — critically small, weak even against classical attacks")
            remediations.append(REMEDIATION_MAP["SMALL_KEY"])
            return 35.0, findings, remediations
        elif size == 2048:
            findings.append(f"⚠️  RSA-{size} — standard size but quantum computers will break this regardless of size")
            return 15.0, findings, remediations
        else:
            findings.append(f"ℹ️  RSA-{size} — larger key helps classically, still quantum-broken")
            return 5.0, findings, remediations

    elif "EC" in algo_upper or "ELLIPTIC" in algo_upper:
        if size < 256:
            findings.append(f"🔴 EC-{size} — too small, replace with PQC immediately")
            return 20.0, findings, remediations
        else:
            findings.append(f"ℹ️  EC-{size} — quantum computers break EC regardless of size")
            return 8.0, findings, remediations

    return 5.0, [], []


def score_cert_validity(days_left: int, is_expired: bool) -> tuple[float, list, list]:
    """
    Certificate expiry adds urgency to remediation.
    An expiring cert = perfect moment to upgrade to PQC cert.
    """
    findings = []
    remediations = []

    if is_expired:
        findings.append("🔴 Certificate is EXPIRED — critical, renew immediately")
        remediations.append(REMEDIATION_MAP["EXPIRED_CERT"])
        return 20.0, findings, remediations
    elif days_left < 30:
        findings.append(f"🔴 Certificate expiring in {days_left} days — renew NOW with PQC cert")
        remediations.append(REMEDIATION_MAP["EXPIRING_SOON"])
        return 12.0, findings, remediations
    elif days_left < 90:
        findings.append(f"⚠️  Certificate expiring in {days_left} days — plan PQC migration")
        remediations.append(REMEDIATION_MAP["EXPIRING_SOON"])
        return 6.0, findings, remediations
    else:
        findings.append(f"✅ Certificate valid for {days_left} more days")
        return 0.0, findings, remediations


def detect_pqc_algorithms(cipher_suite: str, key_algorithm: str, sig_algorithm: str) -> list:
    """
    Check if ANY NIST PQC algorithm is present.
    Returns list of detected PQC algorithms.
    """
    detected = []
    combined = f"{cipher_suite} {key_algorithm} {sig_algorithm}".upper()

    for algo in NIST_PQC_ALGORITHMS:
        if algo.upper() in combined:
            detected.append(algo)

    return detected


def assign_label_and_certificate(
    total_score: float,
    pqc_algorithms: list,
    is_vpn: bool
) -> tuple[QuantumLabel, bool, Optional[str]]:
    """
    Your 3-tier label system.
    PQC certificate only awarded if NIST algorithms confirmed.

    This is YOUR original design — the logic that makes the scanner
    useful beyond just showing numbers.
    """
    # ── Check for actual PQC algorithms first ─────────────────────
    has_nist_pqc = len(pqc_algorithms) > 0
    is_hybrid = any("MLKEM" in a.upper() or "KYBER" in a.upper()
                    for a in pqc_algorithms)
    is_pure_pqc = has_nist_pqc and total_score <= 10

    if is_pure_pqc:
        label = QuantumLabel.FULLY_QUANTUM_SAFE
        is_pqc_ready = True
        cert = "🏆 POST QUANTUM CRYPTOGRAPHY (PQC) READY"
        return label, is_pqc_ready, cert

    elif is_hybrid or (total_score <= 20):
        label = QuantumLabel.FULLY_QUANTUM_SAFE
        is_pqc_ready = True
        cert = "✅ Fully Quantum Safe — NIST PQC Algorithms Confirmed"
        return label, is_pqc_ready, cert

    elif total_score <= 59:
        label = QuantumLabel.QUANTUM_TRANSITIONING
        is_pqc_ready = False
        cert = None
        return label, is_pqc_ready, cert

    else:
        label = QuantumLabel.QUANTUM_VULNERABLE
        is_pqc_ready = False
        cert = None
        return label, is_pqc_ready, cert


# ══════════════════════════════════════════════════════════════════
# MASTER SCORING FUNCTION
# ══════════════════════════════════════════════════════════════════

def calculate_risk_score(cbom_entry: dict) -> RiskScore:
    """
    Takes one CBOM entry (from main.py's scan loop)
    and outputs a complete RiskScore object.

    Weighted formula:
      40% Key Exchange  ← most critical for HNDL
      25% Signature     ← cert trust chain
      20% TLS Version   ← protocol security
      10% Key Size      ← classical strength bonus
       5% Cert Validity ← urgency factor
    """

    host    = cbom_entry.get("host", "unknown")
    port    = cbom_entry.get("port", 443)
    service = cbom_entry.get("service", "HTTPS")

    cipher_suite  = cbom_entry.get("cipher_suite", "") or ""
    key_algorithm = cbom_entry.get("key_algorithm", "") or ""
    sig_algorithm = cbom_entry.get("signature_algorithm", "") or ""
    tls_version   = cbom_entry.get("tls_version", "") or ""
    key_size      = cbom_entry.get("key_size", 0)
    days_left     = cbom_entry.get("days_left", 365)
    is_expired    = cbom_entry.get("is_expired", False)
    is_vpn        = cbom_entry.get("is_vpn", False)
    hndl_mult     = cbom_entry.get("hndl_multiplier", 1.0)

    result = RiskScore(host=host, port=port, service=service)
    result.hndl_multiplier = hndl_mult

    all_findings    = []
    all_remediations = []

    # ── Score each component ──────────────────────────────────────
    ke_score, ke_findings, ke_rems = score_key_exchange(cipher_suite)
    sig_score, sig_findings, sig_rems = score_signature(sig_algorithm, key_algorithm)
    tls_score, tls_findings, tls_rems = score_tls_version(tls_version)
    size_score, size_findings, size_rems = score_key_size(key_algorithm, key_size)
    validity_score, val_findings, val_rems = score_cert_validity(days_left, is_expired)

    result.key_exchange_score  = ke_score
    result.signature_score     = sig_score
    result.tls_version_score   = tls_score
    result.key_size_penalty    = size_score
    result.cert_validity_score = validity_score

    all_findings    += ke_findings + sig_findings + tls_findings + size_findings + val_findings
    all_remediations += ke_rems + sig_rems + tls_rems + size_rems + val_rems

    # ── Weighted total ─────────────────────────────────────────────
    base_score = (
        ke_score    * 0.40 +
        sig_score   * 0.25 +
        tls_score   * 0.20 +
        size_score  * 0.10 +
        validity_score * 0.05
    )

    # ── VPN HNDL multiplier boosts the risk score ──────────────────
    # VPN traffic is harvested long-term = higher urgency
    if is_vpn and hndl_mult > 1.0:
        boost = min((hndl_mult - 1.0) * 15, 20)  # max +20 points
        base_score = min(base_score + boost, 100)
        all_findings.insert(0,
            f"⚠️  VPN endpoint — HNDL multiplier {hndl_mult}x applied. "
            f"Long-lived tunnel traffic is prime harvest target."
        )
        # Add VPN-specific remediation
        if "openvpn" in service.lower():
            all_remediations.insert(0, REMEDIATION_MAP["VPN_OPENVPN"])
        elif "ipsec" in service.lower() or "ikev" in service.lower():
            all_remediations.insert(0, REMEDIATION_MAP["VPN_IPSEC"])
        elif "wireguard" in service.lower():
            all_remediations.insert(0, REMEDIATION_MAP["VPN_WIREGUARD"])

    result.total_score = round(base_score, 1)

    # ── Detect PQC ────────────────────────────────────────────────
    pqc_detected = detect_pqc_algorithms(cipher_suite, key_algorithm, sig_algorithm)
    result.pqc_algorithms_detected = pqc_detected

    # ── Assign label + certificate ────────────────────────────────
    label, is_pqc, cert = assign_label_and_certificate(
        result.total_score, pqc_detected, is_vpn
    )
    result.label               = label
    result.is_pqc_ready        = is_pqc
    result.certificate_awarded = cert

    # ── Deduplicate findings + remediations ───────────────────────
    result.findings     = list(dict.fromkeys(all_findings))
    result.remediations = list(dict.fromkeys(all_remediations))

    return result


def score_cbom(cbom_entries: list) -> list[RiskScore]:
    """
    Score an entire CBOM list.
    Returns sorted by risk score — highest risk first.
    This is your Priority Queue output.
    """
    scores = [calculate_risk_score(entry) for entry in cbom_entries]
    scores.sort(key=lambda x: x.total_score, reverse=True)
    return scores


# ══════════════════════════════════════════════════════════════════
# TEST RUNNER — Simulates realistic bank scan data
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    from rich.console import Console
    from rich.table   import Table
    from rich.panel   import Panel
    from rich.text    import Text

    console = Console()

    # Simulated CBOM entries — what your scanner would produce
    test_cbom = [
        {
            "host": "www.testbank.com",       "port": 443,
            "service": "HTTPS",               "is_vpn": False,
            "hndl_multiplier": 1.0,
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "key_algorithm": "RSAPublicKey",  "signature_algorithm": "sha256_with_rsa_encryption",
            "tls_version": "TLSv1.2",         "key_size": 2048,
            "days_left": 180,                 "is_expired": False,
        },
        {
            "host": "api.testbank.com",        "port": 443,
            "service": "HTTPS",                "is_vpn": False,
            "hndl_multiplier": 1.0,
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "key_algorithm": "EllipticCurvePublicKey", "signature_algorithm": "ecdsa_with_sha256",
            "tls_version": "TLSv1.3",          "key_size": 256,
            "days_left": 45,                   "is_expired": False,
        },
        {
            "host": "vpn.testbank.com",        "port": 1194,
            "service": "OpenVPN",              "is_vpn": True,
            "hndl_multiplier": 2.0,
            "cipher_suite": "DHE_RSA_AES256",
            "key_algorithm": "RSAPublicKey",   "signature_algorithm": "sha256_with_rsa_encryption",
            "tls_version": "TLSv1.2",          "key_size": 2048,
            "days_left": 300,                  "is_expired": False,
        },
        {
            "host": "legacy.testbank.com",     "port": 443,
            "service": "HTTPS",                "is_vpn": False,
            "hndl_multiplier": 1.0,
            "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
            "key_algorithm": "RSAPublicKey",   "signature_algorithm": "sha256_with_rsa_encryption",
            "tls_version": "TLSv1.0",          "key_size": 1024,
            "days_left": -5,                   "is_expired": True,
        },
        {
            "host": "pqc.testbank.com",        "port": 443,
            "service": "HTTPS",                "is_vpn": False,
            "hndl_multiplier": 1.0,
            "cipher_suite": "TLS_ML-KEM-768_AES_256_GCM_SHA384",
            "key_algorithm": "ML-DSA-65",      "signature_algorithm": "ML-DSA-65",
            "tls_version": "TLSv1.3",          "key_size": 0,
            "days_left": 365,                  "is_expired": False,
        },
    ]

    scores = score_cbom(test_cbom)

    # ── Main results table ─────────────────────────────────────────
    table = Table(title="Quantum Risk Scores — CBOM", show_lines=True, width=110)
    table.add_column("Host",          style="cyan",    width=25)
    table.add_column("Service",       style="white",   width=12)
    table.add_column("KE Score",      style="yellow",  width=9,  justify="center")
    table.add_column("Sig Score",     style="yellow",  width=9,  justify="center")
    table.add_column("TLS Score",     style="yellow",  width=9,  justify="center")
    table.add_column("RISK /100",     style="bold",    width=10, justify="center")
    table.add_column("Label",         style="bold",    width=22)
    table.add_column("PQC Cert",      style="green",   width=10, justify="center")

    label_colors = {
        QuantumLabel.QUANTUM_VULNERABLE:   "[red]🔴 VULNERABLE[/red]",
        QuantumLabel.QUANTUM_TRANSITIONING:"[yellow]🟡 TRANSITIONING[/yellow]",
        QuantumLabel.FULLY_QUANTUM_SAFE:   "[green]🟢 QUANTUM SAFE[/green]",
    }

    for s in scores:
        pqc_badge = "[green]✓ AWARDED[/green]" if s.certificate_awarded else "[red]✗ Not yet[/red]"
        table.add_row(
            s.host,
            s.service,
            str(s.key_exchange_score),
            str(s.signature_score),
            str(s.tls_version_score),
            f"[bold]{s.total_score}[/bold]",
            label_colors[s.label],
            pqc_badge,
        )

    console.print(table)

    # ── Detailed breakdown per host ────────────────────────────────
    for s in scores:
        color = "red" if s.label == QuantumLabel.QUANTUM_VULNERABLE else \
                "yellow" if s.label == QuantumLabel.QUANTUM_TRANSITIONING else "green"

        console.print(f"\n[bold {color}]{'─'*60}[/bold {color}]")
        console.print(f"[bold {color}]  {s.host}:{s.port} — Risk Score: {s.total_score}/100[/bold {color}]")
        console.print(f"[bold {color}]  {s.label.value}[/bold {color}]")

        if s.certificate_awarded:
            console.print(Panel(
                f"[bold green]{s.certificate_awarded}[/bold green]\n"
                f"PQC Algorithms: {', '.join(s.pqc_algorithms_detected)}",
                title="🏆 Certificate Awarded",
                border_style="green"
            ))

        if s.findings:
            console.print("  [bold]Findings:[/bold]")
            for f in s.findings:
                console.print(f"    {f}")

        if s.remediations and not s.is_pqc_ready:
            console.print("  [bold yellow]Remediation Actions:[/bold yellow]")
            for i, r in enumerate(s.remediations[:3], 1):
                console.print(f"    {i}. {r}")

    # ── Summary stats ──────────────────────────────────────────────
    console.print(f"\n[bold]{'═'*60}[/bold]")
    console.print("[bold]SUMMARY[/bold]")
    console.print(f"  Total assets scored  : {len(scores)}")
    console.print(f"  [red]Quantum Vulnerable   : {sum(1 for s in scores if s.label == QuantumLabel.QUANTUM_VULNERABLE)}[/red]")
    console.print(f"  [yellow]Transitioning        : {sum(1 for s in scores if s.label == QuantumLabel.QUANTUM_TRANSITIONING)}[/yellow]")
    console.print(f"  [green]Fully Quantum Safe   : {sum(1 for s in scores if s.label == QuantumLabel.FULLY_QUANTUM_SAFE)}[/green]")
    console.print(f"  [green]PQC Certificates     : {sum(1 for s in scores if s.certificate_awarded)}[/green]")
