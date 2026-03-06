import ssl
import socket
import json
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# ── Algorithms that quantum computers WILL break ──────────────────
QUANTUM_VULNERABLE_KEY_ALGORITHMS = [
    "RSA", "DSA", "EC", "ECDSA", "ECDH"
]

# ── NIST approved Post-Quantum algorithms ─────────────────────────
QUANTUM_SAFE_KEY_ALGORITHMS = [
    "ML-KEM", "ML-DSA", "SLH-DSA",         # NIST FIPS 203/204/205
    "CRYSTALS-Kyber", "CRYSTALS-Dilithium", # Older names, same thing
    "FALCON", "SPHINCS+"
]


def get_certificate(hostname: str, port: int = 443) -> dict:
    """
    Connects to a host, grabs its TLS certificate,
    and returns everything your scanner needs.
    """

    result = {
        "host": hostname,
        "port": port,
        "reachable": False,
        "certificate": {},
        "error": None
    }

    try:
        # ── Step 1: Create SSL context ─────────────────────────────
        context = ssl.create_default_context()

        # ── Step 2: Open raw socket connection ─────────────────────
        with socket.create_connection(
            (hostname, port), timeout=10
        ) as sock:

            # ── Step 3: Wrap socket with TLS ───────────────────────
            with context.wrap_socket(
                sock, server_hostname=hostname
            ) as tls_sock:

                result["reachable"] = True

                # ── Step 4: Pull raw certificate bytes ─────────────
                raw_cert = tls_sock.getpeercert(binary_form=True)

                # ── Step 5: Also grab negotiated cipher right here ──
                cipher_info = tls_sock.cipher()
                tls_version = tls_sock.version()

                # Store cipher data alongside cert
                result["negotiated_cipher"] = {
                    "name": cipher_info[0],      # e.g TLS_AES_256_GCM_SHA384
                    "protocol": cipher_info[1],  # e.g TLSv1.3
                    "bits": cipher_info[2]        # e.g 256
                }
                result["tls_version"] = tls_version

        # ── Step 6: Parse certificate using cryptography library ────
        cert = x509.load_der_x509_certificate(raw_cert, default_backend())

        # ── Step 7: Extract everything ────────────────────
        result["certificate"] = extract_cert_fields(cert)

    except socket.timeout:
        result["error"] = "Connection timed out"
    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {str(e)}"
    except ConnectionRefusedError:
        result["error"] = "Connection refused - port closed"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"

    return result


def extract_cert_fields(cert) -> dict:
    """
    Pulls out every field relevant to quantum vulnerability assessment.
    This is your forensics work — extracting structured data from binary.
    """

    # ── Public Key Info (Most Important for Quantum Risk) ──────────
    public_key = cert.public_key()
    key_algorithm = type(public_key).__name__   # RSAPublicKey, etc
    
    try:
        key_size = public_key.key_size          # 2048, 4096, 256, etc
    except AttributeError:
        key_size = "Unknown"

    # ── Subject Alternative Names (Graph Expansion Nodes) ─────
    try:
        san_extension = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        sans = san_extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    # ── Signature Algorithm (Second Most Important) ─────────────────
    sig_algo = cert.signature_algorithm_oid._name  

    # ── Validity Period ─────────────────────────────────────────────
    now = datetime.utcnow()
    expiry = cert.not_valid_after_utc.replace(tzinfo=None)
    days_left = (expiry - now).days

    return {
        # Identity
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": str(cert.serial_number),

        # Validity
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_until": cert.not_valid_after_utc.isoformat(),
        "days_until_expiry": days_left,
        "is_expired": days_left < 0,

        # Crypto fields — THE SCORE 
        "public_key_algorithm": key_algorithm,
        "key_size_bits": key_size,
        "signature_algorithm": sig_algo,

        # Graph expansion
        "subject_alternative_names": list(sans),

        # Quick quantum flag
        "is_quantum_vulnerable": is_quantum_vulnerable(key_algorithm),
        "quantum_risk_reason": get_risk_reason(key_algorithm, key_size)
    }

def is_quantum_vulnerable(key_algorithm: str) -> bool:
    """
    RSA and EC keys are broken by Shor's algorithm.
    Returns True if this certificate will NOT survive quantum era.
    """
    for vulnerable in QUANTUM_VULNERABLE_KEY_ALGORITHMS:
        if vulnerable.lower() in key_algorithm.lower():
            return True
    return False

def get_risk_reason(key_algorithm: str, key_size) -> str:
    """
    Human-readable explanation of WHY this is vulnerable.
    This text goes into your final CBOM report.
    """
    if "RSA" in key_algorithm:
        return (
            f"RSA-{key_size} is broken by Shor's algorithm on CRQCs. "
            f"Migrate to ML-KEM (CRYSTALS-Kyber) for key exchange."
        )
    elif "EC" in key_algorithm:
        return (
            f"Elliptic Curve ({key_size}-bit) is vulnerable to quantum attacks. "
            f"Replace with ML-DSA (CRYSTALS-Dilithium) for signatures."
        )
    else:
        return "Algorithm status unknown — manual review required."


