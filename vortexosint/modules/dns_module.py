"""
DNS Module - Full DNS Record Dump, Reverse DNS (PTR) & Passive Subdomain Enumeration.
"""

import argparse
import socket
from typing import Any, Dict, List

from vortexosint.core.banner import print_module_banner
from vortexosint.core.colors import Colors
from vortexosint.core.output import output_results as _output_results

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; VortexOSINT/1.0)"}
DEFAULT_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")


def query_dns_records(domain: str, record_types: tuple = DEFAULT_RECORD_TYPES) -> Dict[str, Any]:
    """Query multiple DNS record types for a domain."""
    clean = (domain or "").strip().lower().rstrip(".")
    records: Dict[str, List[str]] = {}

    try:
        import dns.resolver  # type: ignore

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        for rtype in record_types:
            try:
                answers = resolver.resolve(clean, rtype)
                records[rtype] = sorted({str(rdata).strip() for rdata in answers})
            except Exception:
                continue
    except ImportError:
        # Stdlib fallback for A/AAAA
        try:
            infos = socket.getaddrinfo(clean, None)
            a_recs = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
            aaaa_recs = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
            if a_recs:
                records["A"] = a_recs
            if aaaa_recs:
                records["AAAA"] = aaaa_recs
        except Exception as e:
            return {"domain": clean, "error": str(e)}

    return {
        "domain": clean,
        "record_types_found": list(records.keys()),
        "records": records,
    }


def reverse_dns_lookup(ip: str) -> Dict[str, Any]:
    """Perform a Reverse DNS (PTR) lookup for an IP address."""
    target = (ip or "").strip()
    try:
        hostname, aliases, addrs = socket.gethostbyaddr(target)
        return {
            "ip": target,
            "hostname": hostname,
            "aliases": list(aliases),
            "addresses": list(addrs),
        }
    except Exception as e:
        return {"ip": target, "hostname": None, "error": str(e)}


def enumerate_subdomains_passive(domain: str, timeout: int = 15, limit: int = 150) -> Dict[str, Any]:
    """Passively enumerate subdomains via crt.sh and HackerTarget."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}

    clean = (domain or "").strip().lower().rstrip(".")
    subs = set()
    sources_used: List[str] = []

    # 1. crt.sh
    try:
        r = requests.get(f"https://crt.sh/?q=%.{clean}&output=json", headers=_HEADERS, timeout=timeout)
        if r.status_code == 200:
            sources_used.append("crt.sh")
            for item in r.json():
                for line in item.get("name_value", "").splitlines():
                    h = line.strip().lower().lstrip("*.")
                    if h.endswith(f".{clean}") or h == clean:
                        subs.add(h)
    except Exception:
        pass

    # 2. HackerTarget hostsearch
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={clean}", headers=_HEADERS, timeout=timeout)
        if r.status_code == 200 and "error" not in r.text.lower()[:40]:
            sources_used.append("hackertarget")
            for line in r.text.splitlines():
                host = line.split(",", 1)[0].strip().lower()
                if host.endswith(f".{clean}") or host == clean:
                    subs.add(host)
    except Exception:
        pass

    sorted_subs = sorted(subs)
    return {
        "domain": clean,
        "sources": sources_used,
        "count": len(sorted_subs),
        "subdomains": sorted_subs[:limit],
    }


def run(args: argparse.Namespace) -> int:
    """Run the DNS module."""
    print_module_banner("DNS", "DNS Record Dump, Reverse PTR & Passive Subdomain Finder")
    domain = getattr(args, "domain", None)
    rev_ip = getattr(args, "reverse", None)
    do_subs = getattr(args, "subdomains", False)

    if not any([domain, rev_ip]):
        print(f"{Colors.RED}[!] Specify --domain <domain> or --reverse <ip>{Colors.RESET}")
        return 1

    results: Dict[str, Any] = {}
    if domain:
        print(f"\n{Colors.CYAN}[*] Querying DNS records for: {Colors.BOLD}{domain}{Colors.RESET}")
        findings: Dict[str, Any] = {"dns": query_dns_records(domain)}
        if do_subs:
            print(f"  {Colors.YELLOW}[~] Enumerating passive subdomains (crt.sh / HackerTarget)...{Colors.RESET}")
            findings["subdomains"] = enumerate_subdomains_passive(domain)
        results[domain] = {"target": domain, "type": "dns", "findings": findings}

    if rev_ip:
        print(f"\n{Colors.CYAN}[*] Reverse DNS (PTR) for: {Colors.BOLD}{rev_ip}{Colors.RESET}")
        results[rev_ip] = {"target": rev_ip, "type": "reverse_dns", "findings": reverse_dns_lookup(rev_ip)}

    _output_results(results, args, mode="target")
    return 0
