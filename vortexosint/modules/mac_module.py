"""
MAC Module - MAC Address Normalization, Randomization Detection & OUI Vendor Lookup.
"""

import argparse
import re
from typing import Any, Dict, Optional

from vortexosint.core.banner import print_module_banner
from vortexosint.core.colors import Colors
from vortexosint.core.output import output_results as _output_results

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; VortexOSINT/1.0)"}

# Compact local OUI vendor table (common hardware, IoT, hypervisors)
LOCAL_OUI_DB: Dict[str, str] = {
    "00:00:0C": "Cisco Systems, Inc.",
    "00:05:69": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",
    "00:15:5D": "Microsoft Corporation (Hyper-V)",
    "00:16:3E": "Xensource, Inc. (Xen)",
    "00:1A:11": "Google, Inc.",
    "00:1B:63": "Apple, Inc.",
    "00:1C:42": "Parallels, Inc.",
    "00:25:90": "Super Micro Computer, Inc.",
    "00:50:56": "VMware, Inc.",
    "08:00:27": "Oracle / VirtualBox",
    "18:FE:34": "Espressif Inc. (ESP8266/ESP32)",
    "24:0A:C4": "Espressif Inc.",
    "28:CF:E9": "Apple, Inc.",
    "3C:22:FB": "Apple, Inc.",
    "44:D9:E7": "Ubiquiti Inc.",
    "50:C7:BF": "TP-Link Technologies Co., Ltd.",
    "52:54:00": "QEMU / KVM Virtual NIC",
    "64:70:02": "TP-Link Technologies Co., Ltd.",
    "74:AC:B9": "Ubiquiti Inc.",
    "88:71:B1": "ARRIS Group, Inc.",
    "9C:B6:D0": "Rivet Networks (Killer Wi-Fi)",
    "A4:5E:60": "Apple, Inc.",
    "B8:27:EB": "Raspberry Pi Foundation",
    "C8:2A:14": "Apple, Inc.",
    "D4:CA:6D": "Routerboard.com (MikroTik)",
    "DC:A6:32": "Raspberry Pi Trading Ltd",
    "E4:5F:01": "Raspberry Pi Trading Ltd",
    "F0:18:98": "Apple, Inc.",
    "FC:EC:DA": "Ubiquiti Inc.",
}


def normalize_mac(raw: str) -> Optional[str]:
    """Normalize a MAC address (colon, hyphen, Cisco dot, or bare hex) to AA:BB:CC:DD:EE:FF."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", (raw or "").strip())
    if len(cleaned) != 12:
        return None
    upper = cleaned.upper()
    return ":".join(upper[i:i + 2] for i in range(0, 12, 2))


def analyze_mac(raw: str, online: bool = True, timeout: int = 8) -> Dict[str, Any]:
    """Analyze a MAC address: format, bit flags (unicast/multicast, LAA/UAA), and OUI vendor."""
    norm = normalize_mac(raw)
    if not norm:
        return {"input": raw, "valid": False, "error": "Invalid MAC address (expected 12 hex digits)"}

    first_octet = int(norm[:2], 16)
    is_multicast = bool(first_octet & 0x01)
    is_local = bool(first_octet & 0x02)
    oui = norm[:8]

    vendor = LOCAL_OUI_DB.get(oui)
    source = "local_db" if vendor else None

    if not vendor and online and not is_local:
        try:
            import requests

            resp = requests.get(f"https://api.macvendors.com/{norm}", headers=_HEADERS, timeout=timeout)
            if resp.status_code == 200 and resp.text.strip():
                vendor = resp.text.strip()
                source = "macvendors.com"
        except Exception:
            pass

    if is_local and not vendor:
        vendor = "Locally Administered / Randomized MAC (no global OUI)"
        source = "bit_analysis"

    return {
        "valid": True,
        "mac_colon": norm,
        "mac_hyphen": norm.replace(":", "-"),
        "mac_cisco": ".".join(norm.replace(":", "")[i:i + 4].lower() for i in range(0, 12, 4)),
        "oui": oui,
        "transmission": "Multicast" if is_multicast else "Unicast",
        "administration": "Locally Administered (Randomized/Spoofed)" if is_local else "Universally Administered (Burned-in)",
        "is_randomized": is_local,
        "vendor": vendor or "Unknown",
        "vendor_source": source or "none",
    }


def run(args: argparse.Namespace) -> int:
    """Run the MAC/OUI module."""
    print_module_banner("MAC", "MAC Address / OUI Vendor & Randomization Analyzer")
    mac = getattr(args, "mac", None)
    if not mac:
        print(f"{Colors.RED}[!] No MAC address specified. Use --mac <AA:BB:CC:DD:EE:FF>{Colors.RESET}")
        return 1

    online = not getattr(args, "offline", False)
    print(f"\n{Colors.CYAN}[*] Analyzing MAC address: {Colors.BOLD}{mac}{Colors.RESET}")
    results = {mac: {"target": mac, "type": "mac", "findings": analyze_mac(mac, online=online)}}
    _output_results(results, args, mode="target")
    return 0
