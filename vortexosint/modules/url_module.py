"""
URL Module - URL Unshortener, Tracking Stripper & Heuristic Phishing Analyzer.
"""

import argparse
import ipaddress
import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from vortexosint.core.banner import print_module_banner
from vortexosint.core.colors import Colors
from vortexosint.core.output import output_results as _output_results

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; VortexOSINT/1.0)"}

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "ref_src", "igshid",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".click", ".zip", ".mov", ".ru", ".work",
}

PHISHING_KEYWORDS = {
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "wallet", "confirm", "password", "paypal", "appleid", "microsoft", "office365",
}


def _normalize(url: str) -> str:
    u = (url or "").strip()
    if u and not u.startswith(("http://", "https://")):
        return f"https://{u}"
    return u


def clean_tracking_params(url: str) -> Dict[str, Any]:
    """Strip common tracking query parameters (utm_*, fbclid, gclid, etc.)."""
    parsed = urlparse(_normalize(url))
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    kept = [(k, v) for k, v in pairs if k.lower() not in TRACKING_PARAMS]
    removed = [k for k, _v in pairs if k.lower() in TRACKING_PARAMS]
    cleaned = urlunparse(parsed._replace(query=urlencode(kept)))
    return {"cleaned_url": cleaned, "removed_params": removed}


def analyze_phishing_heuristics(url: str) -> Dict[str, Any]:
    """Score a URL for common phishing / obfuscation indicators (offline, deterministic)."""
    norm = _normalize(url)
    parsed = urlparse(norm)
    host = (parsed.hostname or "").lower()
    path_q = f"{parsed.path}?{parsed.query}".lower()
    flags: List[str] = []
    score = 0

    if not host:
        return {"url": norm, "error": "Invalid URL (missing hostname)"}

    if parsed.username or parsed.password or "@" in parsed.netloc:
        flags.append("Contains '@' userinfo trick in authority")
        score += 35

    try:
        ipaddress.ip_address(host)
        flags.append("Uses raw IP address instead of domain name")
        score += 30
    except ValueError:
        pass

    if "xn--" in host:
        flags.append("Punycode / IDN homograph domain detected (xn--)")
        score += 25

    labels = [p for p in host.split(".") if p]
    if len(labels) >= 4:
        flags.append(f"Excessive subdomain depth ({len(labels) - 2} subdomains)")
        score += 15

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        flags.append(f"High-abuse TLD detected on {host}")
        score += 15

    if host.count("-") >= 3:
        flags.append("Many hyphens in hostname")
        score += 10

    if len(norm) > 100:
        flags.append(f"Unusually long URL ({len(norm)} chars)")
        score += 10

    matched_kw = sorted({kw for kw in PHISHING_KEYWORDS if kw in host or kw in path_q})
    if matched_kw:
        flags.append(f"Sensitive keywords present: {', '.join(matched_kw[:5])}")
        score += 15 if parsed.scheme == "http" else 10

    if parsed.scheme == "http":
        flags.append("Insecure HTTP scheme (no TLS)")
        score += 10

    score = min(score, 100)
    risk = "HIGH" if score >= 50 else ("MEDIUM" if score >= 25 else "LOW")
    return {
        "url": norm,
        "scheme": parsed.scheme,
        "host": host,
        "port": parsed.port,
        "path": parsed.path or "/",
        "risk_score": score,
        "risk_level": risk,
        "flags": flags,
        **clean_tracking_params(norm),
    }


def unshorten_url(url: str, timeout: int = 10, max_hops: int = 10) -> Dict[str, Any]:
    """Follow HTTP redirects to expand a shortened URL."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}

    current = _normalize(url)
    chain: List[Dict[str, Any]] = []
    try:
        resp = requests.get(current, headers=_HEADERS, timeout=timeout, allow_redirects=True, stream=True)
        for hop in resp.history[:max_hops]:
            chain.append({"status": hop.status_code, "url": hop.url})
        chain.append({"status": resp.status_code, "url": resp.url})
        resp.close()
        return {
            "original_url": current,
            "final_url": resp.url,
            "hops": len(resp.history),
            "redirect_chain": chain,
        }
    except Exception as e:
        return {"original_url": current, "error": str(e)}


def run(args: argparse.Namespace) -> int:
    """Run the URL Unshortener / Phishing Analyzer module."""
    print_module_banner("URL", "URL Unshortener, Tracking Stripper & Phishing Analyzer")
    target = getattr(args, "url", None)
    if not target:
        print(f"{Colors.RED}[!] No URL specified. Use --url <url>{Colors.RESET}")
        return 1

    do_expand = getattr(args, "expand", False)
    do_phish = getattr(args, "phishing", False)
    if not any([do_expand, do_phish]):
        do_expand = do_phish = True

    findings: Dict[str, Any] = {}
    final_target = target

    if do_expand:
        print(f"\n{Colors.CYAN}[*] Expanding redirects for: {Colors.BOLD}{target}{Colors.RESET}")
        exp = unshorten_url(target, timeout=getattr(args, "timeout", 10) or 10)
        findings["unshorten"] = exp
        if exp.get("final_url"):
            final_target = exp["final_url"]

    if do_phish:
        print(f"  {Colors.YELLOW}[~] Running phishing heuristic analysis...{Colors.RESET}")
        findings["phishing_analysis"] = analyze_phishing_heuristics(final_target)

    results = {target: {"target": target, "type": "url", "findings": findings}}
    _output_results(results, args, mode="target")
    return 0
