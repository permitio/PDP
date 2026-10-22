"""Build-time check that the image no longer trusts the compromised eMudhra CAs (PER-17672).

The private keys of eight eMudhra intermediate CAs can be recovered from their certificates
(CVE-2026-111943), so anyone can mint a certificate for any host that a client trusting their
roots accepts. Browsers are covered by Certificate Transparency; the PDP's clients are not, and
trust whatever the image carries. The Dockerfile's Python dependency layer bind-mounts and runs
this as its last step, so it sees exactly what ships. It fails the image build if any trust
store the PDP's TLS clients read still holds a root those intermediates chain to:

* certifi's bundle - requests and httpx verify against it by default.
* the system bundle and certificate directory (/etc/ssl/cert.pem and /etc/ssl/certs, from
  Alpine's ca-certificates) - aiohttp, websockets and the stdlib ssl module through OpenSSL,
  OPA through Go's crypto/x509 and the Rust pdp-server through rustls-platform-verifier.

The fix is certifi >= 2026.10.19 (floored in pyproject.toml) and ca-certificates >= 20261020-r0
(the apk layer's `apk upgrade`). This check is what notices when either goes missing, e.g. an
apk layer replayed from a cache older than the fix. horizon/tests/test_check_trust_store.py
covers it.
"""

import base64
import hashlib
import re
import ssl
import sys
from pathlib import Path

import certifi

# Every root the eight intermediates and their Sectigo cross-signs chain to, by the SHA-256 of
# the root certificate's DER encoding: roots.json on https://emudhra.we-have-a-problem.com/.
# Only the first two were ever in Mozilla's store, which certifi and Alpine follow, and AAA
# Certificate Services had left it before the incident; all four are denied anyway, so a
# bundle built from another store's list cannot bring one back unnoticed.
DISTRUSTED_ROOTS = {
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b": "emSign ECC Root CA - G3",
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4": "AAA Certificate Services",
    "7dd78d5f4f13459a83dff9abbba62edbaf6f2d102bf257fd712f4d9f2746ed8d": "emSign Root TLS CA - G3",
    "f2edaaff3d9b701fb4d14c9f285f8c0bad90fc3bcc1fa07d47f4718edaba34a5": "emSign Root CS CA - G3",
}
# OpenSSL loads both forms from a CA file or directory. A TRUSTED CERTIFICATE block is the
# certificate's DER followed by OpenSSL's trust settings.
PEM_BLOCK = re.compile(
    r"-----BEGIN (?:TRUSTED )?CERTIFICATE-----(.+?)-----END (?:TRUSTED )?CERTIFICATE-----", re.DOTALL
)
LONG_FORM_LENGTH = 0x80


def _first_der_element(der: bytes) -> bytes:
    """The leading DER element - the certificate, without any trust settings after it."""
    length = der[1]
    header = 2
    if length >= LONG_FORM_LENGTH:
        header += length - LONG_FORM_LENGTH
        length = int.from_bytes(der[2:header], "big")
    return der[: header + length]


def fingerprints(text: str) -> set[str]:
    return {hashlib.sha256(_first_der_element(base64.b64decode(body))).hexdigest() for body in PEM_BLOCK.findall(text)}


def trust_stores() -> tuple[list[Path], list[Path]]:
    """certifi's bundle and the system bundle, then the files of the certificate directory.

    Resolved, so /etc/ssl/cert.pem and the /etc/ssl/certs/ca-certificates.crt it links to are
    read once.
    """
    paths = ssl.get_default_verify_paths()
    if not paths.cafile:
        sys.exit("check_trust_store: OpenSSL has no default CA file")
    bundles = [Path(certifi.where()).resolve(), Path(paths.cafile).resolve()]
    # get_default_verify_paths() reports capath as None when the directory does not exist.
    certs_dir = Path(paths.capath).iterdir() if paths.capath else []
    dir_files = sorted({path.resolve() for path in certs_dir if path.is_file()} - set(bundles))
    return bundles, dir_files


def find_distrusted() -> dict[Path, list[str]]:
    bundles, dir_files = trust_stores()
    hits = {}
    for path in bundles + dir_files:
        found = fingerprints(path.read_text(errors="replace")) if path.is_file() else set()
        # A missing or empty bundle would pass without checking anything.
        if path in bundles and not found:
            sys.exit(f"check_trust_store: no certificates in trust store {path}")
        if roots := sorted(DISTRUSTED_ROOTS[fp] for fp in found & DISTRUSTED_ROOTS.keys()):
            hits[path] = roots
    return hits


if __name__ == "__main__":
    if hits := find_distrusted():
        found = "; ".join(f"{path}: {', '.join(roots)}" for path, roots in hits.items())
        sys.exit(f"check_trust_store: compromised eMudhra roots are still trusted (PER-17672): {found}")
