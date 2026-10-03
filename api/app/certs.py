"""CA / サーバ証明書の発行。CA は SHSW_CERT_DIR に ca.pem / ca-key.pem として書き出し、プロキシと共有する。"""
import ipaddress
import os
import re
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERT_DIR = os.environ.get("SHSW_CERT_DIR", "/certs")
CA_CERT_FILE = os.path.join(CERT_DIR, "ca.pem")
CA_KEY_FILE = os.path.join(CERT_DIR, "ca-key.pem")
# mitmproxy 版 (旧) が使っていた鍵+証明書の一体型ファイル
LEGACY_CA_FILE = os.path.join(CERT_DIR, "mitmproxy-ca.pem")
_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


def _write_atomic(path: str, data: bytes, mode: int = 0o644) -> None:
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def generate_ca(common_name: str, organization: str, days: int, key_size: int):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
    ])
    now = datetime.now(timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def write_ca_store(key, cert) -> None:
    """プロキシが読む CA (ca.pem / ca-key.pem) を書き出す。
    鍵を先に書き、最後に証明書を置き換える(プロキシは証明書の変化を検知して読み直す)。"""
    os.makedirs(CERT_DIR, exist_ok=True)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    _write_atomic(CA_KEY_FILE, key_pem, 0o600)
    _write_atomic(CA_CERT_FILE, cert.public_bytes(serialization.Encoding.PEM))


_cert_cache: tuple[tuple[int, int], object] | None = None


def load_ca_cert():
    """CA 証明書のみ読む(秘密鍵の読み込み・検証は重いので避ける)。ファイルの更新時刻でキャッシュ。"""
    global _cert_cache
    st = os.stat(CA_CERT_FILE)
    key = (st.st_mtime_ns, st.st_size)
    if _cert_cache is None or _cert_cache[0] != key:
        with open(CA_CERT_FILE, "rb") as f:
            _cert_cache = (key, x509.load_pem_x509_certificate(f.read()))
    return _cert_cache[1]


def load_ca():
    with open(CA_KEY_FILE, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_FILE, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return key, cert


def ensure_ca() -> None:
    if os.path.exists(CA_CERT_FILE) and os.path.exists(CA_KEY_FILE):
        return
    if os.path.exists(LEGACY_CA_FILE):
        # mitmproxy 版からの移行: 既存の CA をそのまま引き継ぐ(端末の入れ直しは不要)
        with open(LEGACY_CA_FILE, "rb") as f:
            data = f.read()
        m = _CERT_RE.search(data)
        if m:
            key = serialization.load_pem_private_key(data, password=None)
            write_ca_store(key, x509.load_pem_x509_certificate(m.group(0)))
            return
    key, cert = generate_ca("shsw Proxy CA", "shsw", 3650, 2048)
    write_ca_store(key, cert)


def fingerprint(cert) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def ca_info() -> dict:
    cert = load_ca_cert()
    def attr(oid):
        v = cert.subject.get_attributes_for_oid(oid)
        return v[0].value if v else ""
    return {
        "common_name": attr(NameOID.COMMON_NAME),
        "organization": attr(NameOID.ORGANIZATION_NAME),
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint_sha256": ":".join(fingerprint(cert)[i:i + 2] for i in range(0, 64, 2)).upper(),
        "fingerprint_raw": fingerprint(cert),
        "key_size": cert.public_key().key_size,
    }


def ca_cert_bytes(fmt: str) -> bytes:
    cert = load_ca_cert()
    if fmt == "der":
        return cert.public_bytes(serialization.Encoding.DER)
    if fmt == "p12":
        return pkcs12.serialize_key_and_certificates(b"shsw CA", None, cert, None, serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM)


def issue_server_cert(common_name: str, sans: list[str], days: int, key_size: int = 2048) -> dict:
    """CA で署名したサーバ証明書を発行する(鍵は保存しない)。"""
    ca_key, ca_cert = load_ca()
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    names = []
    for s in [common_name, *sans]:
        s = s.strip()
        if not s:
            continue
        try:
            gn = x509.IPAddress(ipaddress.ip_address(s))
        except ValueError:
            gn = x509.DNSName(s)
        if gn not in names:
            names.append(gn)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return {
        "serial": format(cert.serial_number, "x"),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "key_pem": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
        "ca_pem": ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
    }
