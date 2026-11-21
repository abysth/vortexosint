"""
Decode Module - Mini CyberChef CLI (Base64/Hex/URL/ROT13, JWT, Hash-ID, Timestamp, CIDR)
"""

import argparse
import base64
import codecs
import datetime
import ipaddress
import json
import re
from typing import Any, Dict, List
from urllib.parse import quote, unquote

from vortexosint.core.banner import print_module_banner
from vortexosint.core.colors import Colors
from vortexosint.core.output import output_results as _output_results


def transform_base64(value: str, encode: bool = False) -> str:
    if encode:
        return base64.b64encode(value.encode("utf-8")).decode("ascii")
    padded = value.strip() + "=" * (-len(value.strip()) % 4)
    return base64.b64decode(padded).decode("utf-8", errors="replace")


def transform_hex(value: str, encode: bool = False) -> str:
    if encode:
        return value.encode("utf-8").hex()
    cleaned = re.sub(r"\s+", "", value).removeprefix("0x")
    return bytes.fromhex(cleaned).decode("utf-8", errors="replace")


def transform_url(value: str, encode: bool = False) -> str:
    return quote(value, safe="") if encode else unquote(value)


def transform_rot13(value: str) -> str:
    return codecs.decode(value, "rot_13")


def decode_jwt(token: str) -> Dict[str, Any]:
    """Decode a JWT header and payload without verifying the signature."""
    parts = (token or "").strip().split(".")
    if len(parts) not in (2, 3):
        return {"error": "Invalid JWT format (expected header.payload[.signature])"}

    def _b64url_json(seg: str) -> Any:
        pad = seg + "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(pad).decode("utf-8"))

    try:
        header = _b64url_json(parts[0])
        payload = _b64url_json(parts[1])
    except Exception as e:
        return {"error": f"Could not decode JWT: {e}"}

    info: Dict[str, Any] = {
        "header": header,
        "payload": payload,
        "has_signature": len(parts) == 3 and bool(parts[2]),
    }
    exp = payload.get("exp") if isinstance(payload, dict) else None
    if isinstance(exp, (int, float)):
        exp_dt = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        info["expires_at_utc"] = exp_dt.isoformat()
        info["expired"] = now > exp_dt
    return info


def identify_hash(hash_str: str) -> Dict[str, Any]:
    """Identify probable hash algorithms from format and length."""
    h = (hash_str or "").strip()
    candidates: List[str] = []

    if h.startswith(("$2a$", "$2b$", "$2y$")) and len(h) == 60:
        candidates.append("bcrypt")
    elif h.startswith("$argon2"):
        candidates.append("Argon2")
    elif h.startswith("$6$"):
        candidates.append("SHA-512 crypt (Unix)")
    elif h.startswith("$5$"):
        candidates.append("SHA-256 crypt (Unix)")
    elif re.fullmatch(r"[0-9a-fA-F]+", h):
        by_len = {
            8: ["CRC32", "Adler-32"],
            32: ["MD5", "NTLM", "MD4"],
            40: ["SHA-1", "RIPEMD-160"],
            56: ["SHA-224", "SHA3-224"],
            64: ["SHA-256", "SHA3-256", "BLAKE2s"],
            96: ["SHA-384", "SHA3-384"],
            128: ["SHA-512", "SHA3-512", "BLAKE2b"],
        }
        candidates.extend(by_len.get(len(h), []))

    return {
        "hash": h,
        "length": len(h),
        "candidates": candidates or ["Unknown"],
    }


def convert_timestamp(value: str) -> Dict[str, Any]:
    """Convert Unix epoch seconds/ms to UTC ISO-8601, or ISO-8601 to Unix epoch."""
    raw = (value or "").strip()
    try:
        num = float(raw)
        # Auto-detect milliseconds
        if abs(num) > 1e11:
            num /= 1000.0
        dt = datetime.datetime.fromtimestamp(num, tz=datetime.timezone.utc)
        return {"unix_seconds": int(num), "utc_iso": dt.isoformat()}
    except ValueError:
        try:
            dt = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return {"unix_seconds": int(dt.timestamp()), "utc_iso": dt.astimezone(datetime.timezone.utc).isoformat()}
        except ValueError as e:
            return {"error": f"Invalid timestamp/date: {e}"}


def analyze_cidr(cidr: str) -> Dict[str, Any]:
    """Calculate subnet details for an IPv4/IPv6 CIDR block."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as e:
        return {"error": str(e)}

    num = net.num_addresses
    usable = max(0, num - 2) if net.version == 4 and net.prefixlen < 31 else num
    return {
        "cidr": str(net),
        "version": f"IPv{net.version}",
        "network": str(net.network_address),
        "broadcast": str(net.broadcast_address),
        "netmask": str(net.netmask),
        "prefix_length": net.prefixlen,
        "total_addresses": num,
        "usable_hosts": usable,
    }


def run(args: argparse.Namespace) -> int:
    """Run the Decode / CyberChef-lite module."""
    print_module_banner("DECODE", "Encoding, JWT Decoder, Hash-ID, Timestamp & CIDR Toolkit")
    encode = bool(getattr(args, "encode", False))
    results: Dict[str, Any] = {}

    try:
        if getattr(args, "base64", None) is not None:
            results["base64"] = {"target": args.base64, "type": "base64",
                                 "findings": {"mode": "encode" if encode else "decode",
                                              "result": transform_base64(args.base64, encode)}}
        if getattr(args, "hex", None) is not None:
            results["hex"] = {"target": args.hex, "type": "hex",
                              "findings": {"mode": "encode" if encode else "decode",
                                           "result": transform_hex(args.hex, encode)}}
        if getattr(args, "url", None) is not None:
            results["url"] = {"target": args.url, "type": "url",
                              "findings": {"mode": "encode" if encode else "decode",
                                           "result": transform_url(args.url, encode)}}
        if getattr(args, "rot13", None) is not None:
            results["rot13"] = {"target": args.rot13, "type": "rot13",
                                "findings": {"result": transform_rot13(args.rot13)}}
        if getattr(args, "jwt", None):
            results["jwt"] = {"target": "jwt", "type": "jwt", "findings": decode_jwt(args.jwt)}
        if getattr(args, "hash_id", None):
            results["hash_id"] = {"target": args.hash_id, "type": "hash_id",
                                  "findings": identify_hash(args.hash_id)}
        if getattr(args, "timestamp", None):
            results["timestamp"] = {"target": args.timestamp, "type": "timestamp",
                                    "findings": convert_timestamp(args.timestamp)}
        if getattr(args, "cidr", None):
            results["cidr"] = {"target": args.cidr, "type": "cidr",
                               "findings": analyze_cidr(args.cidr)}
    except Exception as e:
        print(f"{Colors.RED}[!] Transform error: {e}{Colors.RESET}")
        return 1

    if not results:
        print(f"{Colors.RED}[!] Nothing to do. Use --base64, --hex, --url, --rot13, --jwt, --hash-id, --timestamp or --cidr{Colors.RESET}")
        return 1

    _output_results(results, args, mode="target")
    return 0
