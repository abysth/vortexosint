"""
SSL/TLS Module - Certificate inspection & Certificate Transparency (crt.sh) lookup.
"""

import argparse
import datetime
import hashlib
import socket
import ssl
from typing import Any, Dict, List

from vortexosint.core.banner import print_module_banner
from vortexosint.core.colors import Colors
from vortexosint.core.output import output_results as _output_results

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; VortexOSINT/1.0)"}


def _clean_host(target: str) -> str:
    host = (target or "").strip()
    for prefix in ("https://", "http://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/", 1)[0]
    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]
    return host.strip()


def parse_cert_dict(cert: Dict[str, Any], der_bytes: bytes = b"",
                    protocol: str = "", cipher: tuple = ()) -> Dict[str, Any]:
    """Parse a Python ssl.SSLSocket.getpeercert() dictionary into structured findings."""
    subject = {k: v for part in cert.get("subject", ()) for k, v in part}
    issuer = {k: v for part in cert.get("issuer", ()) for k, v in part}
    sans = [val for kind, val in cert.get("subjectAltName", ()) if kind == "DNS"]

    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    days_remaining = None
    expired = None
    if not_after:
        try:
            exp_dt = datetime.datetime.strptime(
                not_after, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(tz=datetime.timezone.utc)
            days_remaining = (exp_dt - now).days
            expired = days_remaining < 0
        except ValueError:
            pass

    info: Dict[str, Any] = {
        "common_name": subject.get("commonName", ""),
        "subject": subject,
        "issuer": issuer,
        "serial_number": cert.get("serialNumber", ""),
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days_remaining,
        "expired": expired,
        "san_count": len(sans),
        "sans": sans[:50],
    }
    if protocol:
        info["tls_version"] = protocol
    if cipher:
        info["cipher"] = cipher[0]
        info["cipher_bits"] = cipher[2] if len(cipher) > 2 else None
    if der_bytes:
        info["sha256_fingerprint"] = hashlib.sha256(der_bytes).hexdigest()
        info["sha1_fingerprint"] = hashlib.sha1(der_bytes).hexdigest()
    return info


def inspect_ssl_cert(host: str, port: int = 443, timeout: int = 10) -> Dict[str, Any]:
    """Connect to host:port over TLS and inspect its peer certificate."""
    clean = _clean_host(host)
    if not clean:
        return {"error": "Empty hostname"}

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((clean, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean) as ssock:
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True) or b""
                protocol = ssock.version() or ""
                cipher = ssock.cipher() or ()
                result = parse_cert_dict(cert, der, protocol=protocol, cipher=cipher)
                result["host"] = clean
                result["port"] = port
                return result
    except Exception as e:
        return {"host": clean, "port": port, "error": str(e)}


def query_crt_sh(domain: str, timeout: int = 15, limit: int = 100) -> Dict[str, Any]:
    """Query crt.sh Certificate Transparency logs for a domain."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}

    clean = _clean_host(domain)
    url = f"https://crt.sh/?q=%.{clean}&output=json"
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=timeout)
        if resp.status_code != 200:
            return {"domain": clean, "error": f"crt.sh returned HTTP {resp.status_code}"}
        entries = resp.json()
    except Exception as e:
        return {"domain": clean, "error": str(e)}

    subdomains = set()
    issuers = set()
    for item in entries:
        name_val = item.get("name_value", "")
        for line in name_val.splitlines():
            h = line.strip().lower().lstrip("*.")
            if h and clean.lower() in h:
                subdomains.add(h)
        iss = item.get("issuer_name", "")
        if iss:
            issuers.add(iss)

    sorted_subs: List[str] = sorted(subdomains)
    return {
        "domain": clean,
        "certificates_found": len(entries),
        "unique_subdomains_count": len(sorted_subs),
        "subdomains": sorted_subs[:limit],
        "issuers": sorted(issuers)[:10],
    }


def run(args: argparse.Namespace) -> int:
    """Run the SSL/TLS module."""
    print_module_banner("SSL", "SSL/TLS Certificate Inspector & Certificate Transparency")
    host = getattr(args, "host", None)
    if not host:
        print(f"{Colors.RED}[!] No host specified. Use --host <domain>{Colors.RESET}")
        return 1

    port = getattr(args, "port", 443) or 443
    timeout = getattr(args, "timeout", 10) or 10
    do_ct = getattr(args, "ct", False)

    print(f"\n{Colors.CYAN}[*] Inspecting TLS certificate for: {Colors.BOLD}{host}:{port}{Colors.RESET}")
    findings: Dict[str, Any] = {"certificate": inspect_ssl_cert(host, port=port, timeout=timeout)}

    if do_ct:
        print(f"  {Colors.YELLOW}[~] Querying crt.sh Certificate Transparency logs...{Colors.RESET}")
        findings["certificate_transparency"] = query_crt_sh(host, timeout=max(timeout, 15))

    results = {host: {"target": host, "type": "ssl", "findings": findings}}
    _output_results(results, args, mode="target")
    return 0
