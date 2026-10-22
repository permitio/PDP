"""Build-time check that the image no longer trusts the compromised eMudhra CAs (PER-17672).

The private keys of eight eMudhra intermediate CAs can be recovered from their certificates
(CVE-2026-111943), so anyone can mint a certificate for any host that a client trusting their
roots accepts. Browsers are covered by Certificate Transparency; the PDP's clients are not, and
trust whatever the image carries. The Dockerfile's Python dependency layer bind-mounts and runs
this as its last step, so it sees exactly what ships. It fails the image build if any trust
store the PDP's TLS clients read still holds either root those intermediates chain to:

* certifi's bundle - requests and httpx verify against it by default.
* the system bundle and certificate directory (/etc/ssl/cert.pem and /etc/ssl/certs, from
  Alpine's ca-certificates) - aiohttp, websockets and the stdlib ssl module through OpenSSL,
  OPA through Go's crypto/x509 and the Rust pdp-server through rustls-platform-verifier.

The fix is certifi >= 2026.10.19 (floored in pyproject.toml) and ca-certificates >= 20261020-r0
(the apk layer's `apk upgrade`). This check is what notices when either goes missing, e.g. an
apk layer replayed from a cache older than the fix.
"""

import hashlib
import re
import ssl
import sys
from pathlib import Path

import certifi

# SHA-256 of each root's DER encoding.
DISTRUSTED_ROOTS = {
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b": "emSign ECC Root CA - G3",
    # Signs a Sectigo cross-sign of each intermediate. Alpine and certifi had already dropped it
    # before the incident; checked anyway, since the cross-signs chain to it.
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4": "AAA Certificate Services",
}
PEM_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)


def fingerprints(path: Path) -> set[str]:
    return {
        hashlib.sha256(ssl.PEM_cert_to_DER_cert(block)).hexdigest()
        for block in PEM_BLOCK.findall(path.read_text(errors="replace"))
    }


def trust_store_files() -> list[Path]:
    """The two bundles, which must exist and hold certificates, then the certificate directory."""
    paths = ssl.get_default_verify_paths()
    bundles = [Path(certifi.where()), Path(paths.cafile or "")]
    for bundle in bundles:
        # A missing or empty bundle would pass the check below without checking anything.
        if not bundle.is_file() or not fingerprints(bundle):
            sys.exit(f"check_trust_store: no certificates in trust store '{bundle}'")
    certs_dir = Path(paths.capath or "")
    return bundles + (sorted(p for p in certs_dir.iterdir() if p.is_file()) if certs_dir.is_dir() else [])


if __name__ == "__main__":
    hits = {
        path: sorted(DISTRUSTED_ROOTS[fp] for fp in found)
        for path in trust_store_files()
        if (found := fingerprints(path) & DISTRUSTED_ROOTS.keys())
    }
    if hits:
        found = "; ".join(f"{path}: {', '.join(roots)}" for path, roots in hits.items())
        sys.exit(f"check_trust_store: compromised eMudhra roots are still trusted (PER-17672): {found}")
