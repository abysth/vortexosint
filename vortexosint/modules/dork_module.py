"""
Dork Module - Google, GitHub & Shodan Dork Generator
"""

import argparse
from typing import Any, Dict, List
from urllib.parse import quote_plus

from vortexosint.core.banner import print_module_banner
from vortexosint.core.colors import Colors
from vortexosint.core.output import output_results as _output_results


def _clean_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    for p in ("http://", "https://"):
        if d.startswith(p):
            d = d[len(p):]
    return d.split("/")[0].split(":")[0]


def generate_dorks(domain: str = "", keyword: str = "", engine: str = "all") -> Dict[str, List[Dict[str, str]]]:
    """Generate categorized Google, GitHub, and Shodan search queries with URLs."""
    d = _clean_domain(domain)
    kw = (keyword or "").strip()
    out: Dict[str, List[Dict[str, str]]] = {}

    if engine in ("all", "google"):
        g_queries = []
        if d:
            g_queries.extend([
                ("Public Documents", f"site:{d} filetype:pdf OR filetype:docx OR filetype:xlsx"),
                ("Login / Admin Pages", f"site:{d} inurl:login OR inurl:admin OR inurl:signin"),
                ("Open Directories", f'site:{d} intitle:"index of"'),
                ("Config / Backup Files", f"site:{d} ext:xml OR ext:conf OR ext:bak OR ext:log OR ext:sql"),
                ("Subdomains", f"site:*.{d} -www.{d}"),
                ("API / Swagger", f"site:{d} inurl:api OR inurl:swagger OR inurl:graphql"),
            ])
        if kw:
            prefix = f"site:{d} " if d else ""
            g_queries.append(("Keyword Match", f'{prefix}"{kw}"'))
        out["google"] = [
            {"category": cat, "query": q, "url": f"https://www.google.com/search?q={quote_plus(q)}"}
            for cat, q in g_queries
        ]

    if engine in ("all", "github"):
        gh_queries = []
        if d:
            gh_queries.extend([
                ("Domain Mentions", f'"{d}"'),
                ("Config / Env Mentions", f'"{d}" filename:.env OR filename:config OR filename:settings'),
                ("API / Endpoints", f'"{d}" "api" OR "endpoint"'),
            ])
        if kw:
            gh_queries.append(("Keyword Code Search", f'"{kw}"' + (f' "{d}"' if d else "")))
        out["github"] = [
            {"category": cat, "query": q, "url": f"https://github.com/search?q={quote_plus(q)}&type=code"}
            for cat, q in gh_queries
        ]

    if engine in ("all", "shodan"):
        sh_queries = []
        if d:
            sh_queries.extend([
                ("Hostname", f"hostname:{d}"),
                ("SSL Certificate CN", f'ssl.cert.subject.cn:"{d}"'),
                ("HTTP Title / Domain", f'http.html:"{d}"'),
            ])
        if kw:
            sh_queries.append(("Keyword Banner", f'"{kw}"'))
        out["shodan"] = [
            {"category": cat, "query": q, "url": f"https://www.shodan.io/search?query={quote_plus(q)}"}
            for cat, q in sh_queries
        ]

    return out


def run(args: argparse.Namespace) -> int:
    """Run the Dork generator module."""
    print_module_banner("DORK", "Google, GitHub & Shodan Dork Generator")
    domain = getattr(args, "domain", None) or ""
    keyword = getattr(args, "keyword", None) or ""
    engine = getattr(args, "engine", "all") or "all"

    if not domain and not keyword:
        print(f"{Colors.RED}[!] Specify --domain and/or --keyword{Colors.RESET}")
        return 1

    label = domain or keyword
    print(f"\n{Colors.CYAN}[*] Generating dorks ({engine}) for: {Colors.BOLD}{label}{Colors.RESET}")
    dorks = generate_dorks(domain=domain, keyword=keyword, engine=engine)
    results = {label: {"target": label, "type": "dorks", "findings": dorks}}
    _output_results(results, args, mode="target")
    return 0
