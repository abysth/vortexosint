"""
EmailSec Module - Email & DNS Security Audit (SPF, DMARC, DKIM, CAA, MTA-STS, Propagation)
"""

import argparse
import concurrent.futures
from typing import Any, Dict, List

from vortexosint.core.banner import print_module_banner
from vortexosint.core.colors import Colors
from vortexosint.core.output import output_results as _output_results

DEFAULT_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]
PUBLIC_RESOLVERS = {
    "Cloudflare (1.1.1.1)": "1.1.1.1",
    "Google (8.8.8.8)": "8.8.8.8",
    "Quad9 (9.9.9.9)": "9.9.9.9",
}


def _clean_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    for p in ("http://", "https://"):
        if d.startswith(p):
            d = d[len(p):]
    return d.split("/")[0].split(":")[0]


def _query_txt(name: str, nameserver: str = "") -> List[str]:
    import dns.resolver  # type: ignore

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    if nameserver:
        resolver.nameservers = [nameserver]
    try:
        answers = resolver.resolve(name, "TXT")
        return ["".join(s.decode("utf-8", errors="replace") for s in r.strings) for r in answers]
    except Exception:
        return []


def analyze_spf(txt_records: List[str]) -> Dict[str, Any]:
    """Parse SPF record strength."""
    spf_recs = [t for t in txt_records if t.lower().startswith("v=spf1")]
    if not spf_recs:
        return {"present": False, "policy": "none", "record": ""}
    rec = spf_recs[0]
    if "-all" in rec:
        policy = "hardfail (-all)"
    elif "~all" in rec:
        policy = "softfail (~all)"
    elif "?all" in rec:
        policy = "neutral (?all)"
    elif "+all" in rec:
        policy = "allow_all (+all - INSECURE)"
    else:
        policy = "unspecified"
    return {"present": True, "policy": policy, "record": rec}


def analyze_dmarc(txt_records: List[str]) -> Dict[str, Any]:
    """Parse DMARC record policy."""
    dmarc_recs = [t for t in txt_records if t.lower().startswith("v=dmarc1")]
    if not dmarc_recs:
        return {"present": False, "policy": "none", "record": ""}
    rec = dmarc_recs[0]
    policy = "unknown"
    for part in rec.split(";"):
        kv = part.strip().lower()
        if kv.startswith("p="):
            policy = kv.split("=", 1)[1].strip()
            break
    return {"present": True, "policy": policy, "record": rec}


def check_dkim_selectors(domain: str, selectors: List[str]) -> Dict[str, str]:
    """Probe common DKIM selectors for TXT records."""
    found: Dict[str, str] = {}

    def _probe(sel: str):
        recs = _query_txt(f"{sel}._domainkey.{domain}")
        for r in recs:
            if "v=dkim1" in r.lower() or "p=" in r.lower():
                return sel, r[:120]
        return sel, ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(selectors)))) as pool:
        for sel, rec in pool.map(_probe, selectors):
            if rec:
                found[sel] = rec
    return found


def check_dns_propagation(domain: str) -> Dict[str, List[str]]:
    """Compare A records across major public DNS resolvers."""
    import dns.resolver  # type: ignore

    def _query(item):
        label, ns = item
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ns]
        resolver.lifetime = 4.0
        try:
            return label, sorted(r.to_text() for r in resolver.resolve(domain, "A"))
        except Exception as e:
            return label, [f"error: {e}"]

    out: Dict[str, List[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PUBLIC_RESOLVERS)) as pool:
        for label, recs in pool.map(_query, PUBLIC_RESOLVERS.items()):
            out[label] = recs
    return out


def audit_domain_emailsec(domain: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Perform full SPF, DMARC, DKIM, CAA, MTA-STS and optional propagation audit."""
    clean = _clean_domain(domain)
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return {"error": "dnspython not installed"}

    print(f"  {Colors.YELLOW}[~] Checking SPF, DMARC, DKIM, CAA & MTA-STS...{Colors.RESET}")
    root_txt = _query_txt(clean)
    spf = analyze_spf(root_txt)
    dmarc = analyze_dmarc(_query_txt(f"_dmarc.{clean}"))

    sel_arg = getattr(args, "selectors", None)
    selectors = [s.strip() for s in sel_arg.split(",") if s.strip()] if sel_arg else DEFAULT_DKIM_SELECTORS
    dkim = check_dkim_selectors(clean, selectors)

    caa: List[str] = []
    try:
        r = dns.resolver.Resolver()
        r.lifetime = 5.0
        caa = [x.to_text() for x in r.resolve(clean, "CAA")]
    except Exception:
        pass

    mta_sts = _query_txt(f"_mta-sts.{clean}")

    # Spoofing risk evaluation
    if spf["present"] and dmarc["present"] and dmarc["policy"] in ("reject", "quarantine"):
        risk = "low"
    elif spf["present"] or dmarc["present"]:
        risk = "medium"
    else:
        risk = "high"

    findings: Dict[str, Any] = {
        "domain": clean,
        "spoofing_risk": risk,
        "spf": spf,
        "dmarc": dmarc,
        "dkim_found": dkim,
        "caa": caa,
        "mta_sts": mta_sts,
    }

    if getattr(args, "propagation", False):
        print(f"  {Colors.YELLOW}[~] Checking DNS propagation (1.1.1.1 / 8.8.8.8 / 9.9.9.9)...{Colors.RESET}")
        findings["propagation_a"] = check_dns_propagation(clean)

    return findings


def run(args: argparse.Namespace) -> int:
    """Run the EmailSec module."""
    print_module_banner("EMAILSEC", "Email & DNS Security Audit (SPF / DMARC / DKIM / CAA)")
    domain = getattr(args, "domain", None)
    if not domain:
        print(f"{Colors.RED}[!] No domain specified. Use --domain <domain>{Colors.RESET}")
        return 1

    print(f"\n{Colors.CYAN}[*] Auditing email/DNS security for: {Colors.BOLD}{domain}{Colors.RESET}")
    results = {domain: {"target": domain, "type": "emailsec", "findings": audit_domain_emailsec(domain, args)}}
    _output_results(results, args, mode="target")
    return 0
