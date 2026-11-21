"""
IOC / Threat Module - IOC Extraction, Defang/Refang & Public Threat Intel Lookups
"""

import argparse
import os
import re
from pathlib import Path
from typing import Any, Dict, List

from vortexosint.core.banner import print_module_banner
from vortexosint.core.colors import Colors
from vortexosint.core.output import output_results as _output_results

_HEADERS = {"User-Agent": "VortexOSINT/1.0"}

_PATTERNS = {
    "urls": re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE),
    "emails": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "eth_addresses": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "btc_addresses": re.compile(r"\b(?:bc1[a-z0-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
}


def defang(text: str) -> str:
    """Safely defang URLs, IPs and domains (http -> hxxp, . -> [.])."""
    out = re.sub(r"https://", "hxxps://", text, flags=re.IGNORECASE)
    out = re.sub(r"http://", "hxxp://", out, flags=re.IGNORECASE)
    out = out.replace(".", "[.]").replace("@", "[@]")
    return out


def refang(text: str) -> str:
    """Restore defanged indicators back to standard form."""
    out = re.sub(r"hxxps://", "https://", text, flags=re.IGNORECASE)
    out = re.sub(r"hxxp://", "http://", out, flags=re.IGNORECASE)
    out = out.replace("[.]", ".").replace("(.)", ".").replace("[@]", "@")
    return out


def extract_iocs(source: str) -> Dict[str, Any]:
    """Extract all IOCs from a file path (if it exists) or raw text."""
    path = Path(source)
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="replace")
        origin = str(path)
    else:
        text = source
        origin = "inline_text"

    normalized = refang(text)
    extracted: Dict[str, List[str]] = {}
    for kind, regex in _PATTERNS.items():
        extracted[kind] = sorted(set(regex.findall(normalized)))

    # Avoid counting ETH addresses as SHA1 or substrings of SHA256
    eth_raw = {a[2:].lower() for a in extracted["eth_addresses"]}
    extracted["sha1"] = [h for h in extracted["sha1"] if h.lower() not in eth_raw]

    total = sum(len(v) for v in extracted.values())
    return {"source": origin, "total_iocs": total, **extracted}


def check_indicator(indicator: str) -> Dict[str, Any]:
    """Query public threat-intel feeds (URLhaus / MalwareBazaar / VirusTotal if key set)."""
    try:
        import requests
    except ImportError:
        return {"indicator": indicator, "error": "requests not installed"}

    ioc = refang(indicator.strip())
    res: Dict[str, Any] = {"indicator": ioc, "sources": {}}

    # 1) Hash check on MalwareBazaar (abuse.ch, free)
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", ioc):
        print(f"  {Colors.YELLOW}[~] Querying MalwareBazaar...{Colors.RESET}")
        try:
            r = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": ioc},
                headers=_HEADERS, timeout=12,
            )
            data = r.json()
            res["sources"]["malwarebazaar"] = {
                "query_status": data.get("query_status"),
                "matches": len(data.get("data") or []),
            }
        except Exception as e:
            res["sources"]["malwarebazaar"] = {"error": str(e)}

    # 2) URL or host check on URLhaus (abuse.ch, free)
    if ioc.startswith(("http://", "https://")):
        print(f"  {Colors.YELLOW}[~] Querying URLhaus...{Colors.RESET}")
        try:
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": ioc},
                headers=_HEADERS, timeout=12,
            )
            data = r.json()
            res["sources"]["urlhaus"] = {
                "query_status": data.get("query_status"),
                "threat": data.get("threat"),
                "url_status": data.get("url_status"),
            }
        except Exception as e:
            res["sources"]["urlhaus"] = {"error": str(e)}
    elif not re.fullmatch(r"[a-fA-F0-9]{32,64}", ioc):
        print(f"  {Colors.YELLOW}[~] Querying URLhaus host...{Colors.RESET}")
        try:
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": ioc},
                headers=_HEADERS, timeout=12,
            )
            data = r.json()
            res["sources"]["urlhaus"] = {
                "query_status": data.get("query_status"),
                "url_count": data.get("url_count", 0),
                "blacklists": data.get("blacklists", {}),
            }
        except Exception as e:
            res["sources"]["urlhaus"] = {"error": str(e)}

    # 3) Optional VirusTotal v3 if VIRUSTOTAL_API_KEY is configured
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if vt_key and re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", ioc):
        print(f"  {Colors.YELLOW}[~] Querying VirusTotal...{Colors.RESET}")
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{ioc}",
                headers={"x-apikey": vt_key}, timeout=12,
            )
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                res["sources"]["virustotal"] = stats
            else:
                res["sources"]["virustotal"] = {"status_code": r.status_code}
        except Exception as e:
            res["sources"]["virustotal"] = {"error": str(e)}

    return res


def run(args: argparse.Namespace) -> int:
    """Run the IOC / Threat Intel module."""
    print_module_banner("IOC", "IOC Extraction, Defang/Refang & Threat Intelligence")
    results: Dict[str, Any] = {}

    if getattr(args, "extract", None):
        print(f"\n{Colors.CYAN}[*] Extracting IOCs...{Colors.RESET}")
        results["extract"] = {"target": args.extract, "type": "ioc_extract", "findings": extract_iocs(args.extract)}

    if getattr(args, "check", None):
        print(f"\n{Colors.CYAN}[*] Checking indicator: {Colors.BOLD}{args.check}{Colors.RESET}")
        results[args.check] = {"target": args.check, "type": "ioc_check", "findings": check_indicator(args.check)}

    if getattr(args, "defang", None):
        results["defang"] = {"target": args.defang, "type": "defang", "findings": {"result": defang(args.defang)}}

    if getattr(args, "refang", None):
        results["refang"] = {"target": args.refang, "type": "refang", "findings": {"result": refang(args.refang)}}

    if not results:
        print(f"{Colors.RED}[!] Nothing to do. Use --extract, --check, --defang or --refang{Colors.RESET}")
        return 1

    _output_results(results, args, mode="target")
    return 0
