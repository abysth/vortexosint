"""
Web Module - Web Reconnaissance & Security Headers Audit
"""

import argparse
from typing import Any, Dict, List
from urllib.parse import urljoin

from vortexosint.core.banner import print_module_banner
from vortexosint.core.colors import Colors
from vortexosint.core.output import output_results as _output_results

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; VortexOSINT/1.0)"}

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", 20),
    "content-security-policy": ("CSP", 25),
    "x-frame-options": ("X-Frame-Options", 15),
    "x-content-type-options": ("X-Content-Type-Options", 15),
    "referrer-policy": ("Referrer-Policy", 10),
    "permissions-policy": ("Permissions-Policy", 15),
}


def _normalize_url(target: str) -> str:
    t = (target or "").strip()
    if not t.startswith(("http://", "https://")):
        return f"https://{t}"
    return t


def audit_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Grade HTTP security headers from A to F."""
    lowered = {k.lower(): v for k, v in headers.items()}
    present: Dict[str, str] = {}
    missing: List[str] = []
    score = 0

    for key, (label, weight) in SECURITY_HEADERS.items():
        if key in lowered and lowered[key].strip():
            present[label] = lowered[key].strip()
            score += weight
        else:
            missing.append(label)

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    return {
        "grade": grade,
        "score": f"{score}/100",
        "present": present,
        "missing": missing,
        "server": lowered.get("server", ""),
        "x_powered_by": lowered.get("x-powered-by", ""),
    }


def check_well_known_files(base_url: str, timeout: int = 10) -> Dict[str, Any]:
    """Fetch robots.txt, sitemap.xml and /.well-known/security.txt."""
    import requests

    paths = {
        "robots.txt": "/robots.txt",
        "sitemap.xml": "/sitemap.xml",
        "security.txt": "/.well-known/security.txt",
    }
    found: Dict[str, Any] = {}
    for name, path in paths.items():
        url = urljoin(base_url, path)
        try:
            resp = requests.get(url, headers=_HEADERS, timeout=timeout, allow_redirects=True)
            if resp.status_code == 200 and resp.text.strip():
                lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
                found[name] = {
                    "exists": True,
                    "url": url,
                    "line_count": len(lines),
                    "preview": lines[:10],
                }
            else:
                found[name] = {"exists": False, "status_code": resp.status_code}
        except Exception as e:
            found[name] = {"exists": False, "error": str(e)}
    return found


def analyze_url(target: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Run web recon checks on a URL or domain."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}

    url = _normalize_url(target)
    do_headers = getattr(args, "headers", False)
    do_files = getattr(args, "files", False)
    do_redirects = getattr(args, "redirects", False)
    if not any([do_headers, do_files, do_redirects]):
        do_headers = do_files = do_redirects = True

    timeout = getattr(args, "timeout", 12) or 12
    findings: Dict[str, Any] = {"url": url}

    try:
        resp = requests.get(url, headers=_HEADERS, timeout=timeout, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)}

    findings["final_url"] = resp.url
    findings["status_code"] = resp.status_code

    if do_redirects:
        chain = [{"status": r.status_code, "url": r.url} for r in resp.history]
        chain.append({"status": resp.status_code, "url": resp.url})
        findings["redirects"] = chain

    if do_headers:
        print(f"  {Colors.YELLOW}[~] Auditing security headers...{Colors.RESET}")
        findings["security_headers"] = audit_security_headers(dict(resp.headers))

    if do_files:
        print(f"  {Colors.YELLOW}[~] Checking robots.txt / sitemap.xml / security.txt...{Colors.RESET}")
        findings["well_known_files"] = check_well_known_files(resp.url, timeout=timeout)

    return findings


def run(args: argparse.Namespace) -> int:
    """Run the Web module."""
    print_module_banner("WEB", "Web Reconnaissance & Security Headers Audit")
    target = getattr(args, "url", None)
    if not target:
        print(f"{Colors.RED}[!] No target specified. Use --url <domain_or_url>{Colors.RESET}")
        return 1

    print(f"\n{Colors.CYAN}[*] Auditing web target: {Colors.BOLD}{target}{Colors.RESET}")
    results = {target: {"target": target, "type": "web", "findings": analyze_url(target, args)}}
    _output_results(results, args, mode="target")
    return 0
