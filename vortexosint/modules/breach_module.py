"""
Breach Module - k-Anonymity Pwned Passwords Check, Email Exposure & Gravatar Lookup.
"""

import argparse
import getpass
import hashlib
import os
from typing import Any, Dict

from vortexosint.core.banner import print_module_banner
from vortexosint.core.colors import Colors
from vortexosint.core.output import output_results as _output_results

_HEADERS = {"User-Agent": "VortexOSINT/1.0"}
PROMPT_SENTINEL = "__prompt__"


def check_pwned_password(password: str, timeout: int = 10) -> Dict[str, Any]:
    """Check if a password appeared in known breaches via HIBP k-Anonymity (SHA-1 prefix only)."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={**_HEADERS, "Add-Padding": "true"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return {"sha1_prefix": prefix, "error": f"HTTP {resp.status_code}"}
        for line in resp.text.splitlines():
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[0].upper() == suffix:
                count = int(parts[1])
                return {
                    "sha1_prefix": prefix,
                    "pwned": count > 0,
                    "occurrences": count,
                    "verdict": "COMPROMISED — change immediately!" if count > 0 else "Not found in HIBP",
                }
        return {
            "sha1_prefix": prefix,
            "pwned": False,
            "occurrences": 0,
            "verdict": "Not found in HIBP",
        }
    except Exception as e:
        return {"sha1_prefix": prefix, "error": str(e)}


def check_email_breach(email: str, timeout: int = 12) -> Dict[str, Any]:
    """Check email exposure via XposedOrNot (free public API) and optional HIBP API key + Gravatar."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}

    clean = (email or "").strip().lower()
    md5_hash = hashlib.md5(clean.encode("utf-8")).hexdigest()
    info: Dict[str, Any] = {
        "email": clean,
        "gravatar_hash": md5_hash,
        "gravatar_url": f"https://www.gravatar.com/avatar/{md5_hash}?d=404",
    }

    # Gravatar existence check
    try:
        g_resp = requests.head(info["gravatar_url"], headers=_HEADERS, timeout=6)
        info["gravatar_exists"] = g_resp.status_code == 200
    except Exception:
        info["gravatar_exists"] = None

    # Free XposedOrNot API
    try:
        x_resp = requests.get(
            f"https://api.xposedornot.com/v1/check-email/{clean}",
            headers=_HEADERS,
            timeout=timeout,
        )
        if x_resp.status_code == 200:
            data = x_resp.json()
            breaches = data.get("breaches", [])
            flat = breaches[0] if (breaches and isinstance(breaches[0], list)) else breaches
            info["xposedornot"] = {
                "exposed": bool(flat),
                "breach_count": len(flat),
                "breaches": flat[:30],
            }
        elif x_resp.status_code == 404:
            info["xposedornot"] = {"exposed": False, "breach_count": 0, "breaches": []}
        else:
            info["xposedornot"] = {"status_code": x_resp.status_code}
    except Exception as e:
        info["xposedornot"] = {"error": str(e)}

    # Optional HIBP v3 if key configured
    hibp_key = os.getenv("HIBP_API_KEY")
    if hibp_key:
        try:
            h_resp = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{clean}",
                headers={**_HEADERS, "hibp-api-key": hibp_key},
                timeout=timeout,
            )
            if h_resp.status_code == 200:
                names = [b.get("Name") for b in h_resp.json()]
                info["hibp"] = {"exposed": True, "breach_count": len(names), "breaches": names}
            elif h_resp.status_code == 404:
                info["hibp"] = {"exposed": False, "breach_count": 0, "breaches": []}
            else:
                info["hibp"] = {"status_code": h_resp.status_code}
        except Exception as e:
            info["hibp"] = {"error": str(e)}

    return info


def run(args: argparse.Namespace) -> int:
    """Run the Breach / Exposure module."""
    print_module_banner("BREACH", "Email Breach Check, Gravatar & k-Anonymity Pwned Passwords")
    email = getattr(args, "email", None)
    pwd = getattr(args, "password", None)

    if not any([email, pwd]):
        print(f"{Colors.RED}[!] Specify --email <addr> or --password{Colors.RESET}")
        return 1

    results: Dict[str, Any] = {}
    if email:
        print(f"\n{Colors.CYAN}[*] Checking email exposure for: {Colors.BOLD}{email}{Colors.RESET}")
        results[email] = {"target": email, "type": "email_breach", "findings": check_email_breach(email)}

    if pwd is not None:
        secret = getpass.getpass("Mot de passe a verifier (k-Anonymity, non envoye): ") if pwd == PROMPT_SENTINEL else pwd
        if not secret:
            print(f"{Colors.YELLOW}[!] Empty password skipped.{Colors.RESET}")
        else:
            print(f"\n{Colors.CYAN}[*] Checking password via HIBP k-Anonymity...{Colors.RESET}")
            results["password_check"] = {"target": "password", "type": "pwned_password",
                                         "findings": check_pwned_password(secret)}

    _output_results(results, args, mode="target")
    return 0
