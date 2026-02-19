#!/usr/bin/env python3
"""
gen_certs.py  —  Generate a self-signed CA + server certificate for NetSentinel.
Also generates a shared API key and writes sentinel_config.json.

Run once before starting the server:
    python3 gen_certs.py
"""

import json
import os
import secrets
import datetime
import ipaddress
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    raise SystemExit("[!] Run:  pip install cryptography")

CERT_DIR = Path("certs")
CERT_DIR.mkdir(exist_ok=True)

# ── helpers ────────────────────────────────────────────────────────────────────

def new_key(bits: int = 4096):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)

def save_key(key, path: Path, password: bytes | None = None):
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, enc)
    )
    path.chmod(0o600)
    print(f"  ✔  {path}")

def save_cert(cert, path: Path):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  ✔  {path}")


# ── CA ─────────────────────────────────────────────────────────────────────────

print("\n[1/3]  Generating CA key & self-signed certificate …")

ca_key  = new_key()
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME,             "NetSentinel CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,       "NetSentinel"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,"Security"),
])

now = datetime.datetime.utcnow()
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(x509.KeyUsage(
        digital_signature=True, content_commitment=False,
        key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=True,
        crl_sign=True, encipher_only=False, decipher_only=False,
    ), critical=True)
    .sign(ca_key, hashes.SHA256())
)

save_key(ca_key, CERT_DIR / "ca.key")
save_cert(ca_cert, CERT_DIR / "ca.crt")


# ── Server cert ────────────────────────────────────────────────────────────────

print("\n[2/3]  Generating server key & certificate (signed by CA) …")

srv_key  = new_key(2048)
srv_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME,       "NetSentinel Server"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetSentinel"),
])

san = x509.SubjectAlternativeName([
    x509.DNSName("localhost"),
    x509.DNSName("netsentinel.local"),
    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
])

srv_cert = (
    x509.CertificateBuilder()
    .subject_name(srv_name)
    .issuer_name(ca_name)
    .public_key(srv_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=825))
    .add_extension(san, critical=False)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(
        digital_signature=True, content_commitment=False,
        key_encipherment=True, data_encipherment=False,
        key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False,
    ), critical=True)
    .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    .sign(ca_key, hashes.SHA256())
)

save_key(srv_key, CERT_DIR / "server.key")
save_cert(srv_cert, CERT_DIR / "server.crt")


# ── API key + config ───────────────────────────────────────────────────────────

print("\n[3/3]  Generating API key and writing sentinel_config.json …")

api_key = secrets.token_urlsafe(32)
config  = {
    "server_host": "0.0.0.0",
    "server_port": 8443,
    "api_key":     api_key,
    "ca_cert":     str(CERT_DIR / "ca.crt"),
    "server_cert": str(CERT_DIR / "server.crt"),
    "server_key":  str(CERT_DIR / "server.key"),
}

Path("sentinel_config.json").write_text(json.dumps(config, indent=2))
os.chmod("sentinel_config.json", 0o600)
print("  ✔  sentinel_config.json")

print(f"""
╔══════════════════════════════════════════════════════════╗
║                    Setup Complete                        ║
╠══════════════════════════════════════════════════════════╣
║  CA cert:      certs/ca.crt                              ║
║  Server cert:  certs/server.crt                          ║
║  Server key:   certs/server.key                          ║
║  Config:       sentinel_config.json                      ║
╠══════════════════════════════════════════════════════════╣
║  API Key: {api_key:<48} ║
║                                                          ║
║  Keep this secret — distribute sentinel_config.json      ║
║  to each agent host (agents only need api_key + ca_cert) ║
╚══════════════════════════════════════════════════════════╝

Next steps:
  1.  python3 sentinel_server.py          # on your server
  2.  sudo python3 sentinel_agent.py      # on each monitored host
""")
