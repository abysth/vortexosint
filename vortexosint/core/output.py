"""
Centralized output formatting and file export for VortexOSINT modules.
Supports JSON, plain text, and properly escaped CSV with UTF-8 encoding.
"""

import argparse
import csv
import io
import json
from typing import Any, Dict

from vortexosint.core.colors import Colors


def format_dict(d: Dict[str, Any], indent: int = 0) -> str:
    """Format a nested dictionary as indented text."""
    lines = []
    prefix = " " * indent
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{prefix}{k}:")
            lines.append(format_dict(v, indent + 2))
        elif isinstance(v, list):
            lines.append(f"{prefix}{k}:")
            for item in v:
                if isinstance(item, dict):
                    lines.append(format_dict(item, indent + 2))
                else:
                    lines.append(f"{prefix}  - {item}")
        else:
            lines.append(f"{prefix}{k}: {v}")
    return "\n".join(lines)


def flatten_dict(d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    """Flatten a nested dictionary into dot-separated keys."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            items.append((new_key, str(v)))
        else:
            items.append((new_key, v))
    return dict(items)


def format_results_txt(results: Dict[str, Any], mode: str = "target") -> str:
    """Format results as human-readable text."""
    lines = []
    if mode == "category":
        for key, data in results.items():
            lines.append(f"\n{key.upper()}:")
            lines.append("-" * 50)
            if isinstance(data, dict):
                lines.append(format_dict(data, indent=2))
            else:
                lines.append(str(data))
    elif mode == "file":
        for file_path, data in results.items():
            lines.append(f"\nFile: {file_path}")
            lines.append("-" * 50)
            findings = data.get("findings", {}) if isinstance(data, dict) else {}
            basic = findings.get("basic", {}) if isinstance(findings, dict) else {}
            size_bytes = data.get("size", "N/A") if isinstance(data, dict) else "N/A"
            mime = data.get("mime_type", "N/A") if isinstance(data, dict) else "N/A"
            modified = data.get("modified", "N/A") if isinstance(data, dict) else "N/A"
            lines.append(f"Size: {basic.get('size_human', 'N/A')} ({size_bytes} bytes)")
            lines.append(f"Type: {mime}")
            lines.append(f"Modified: {modified}")
            lines.append("")
            lines.append(format_dict(findings, indent=2))
    else:
        for target, data in results.items():
            if isinstance(data, dict) and "findings" in data:
                target_type = data.get("type", "unknown")
                lines.append(f"\nTarget: {target} ({target_type})")
                lines.append("-" * 50)
                lines.append(format_dict(data["findings"], indent=2))
            elif isinstance(data, dict):
                lines.append(f"\nTarget: {target}")
                lines.append("-" * 50)
                lines.append(format_dict(data, indent=2))
            else:
                lines.append(f"\nTarget: {target}: {data}")
    return "\n".join(lines)


def format_results_csv(results: Dict[str, Any], mode: str = "target") -> str:
    """Format results as RFC 4180-compliant CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")

    if mode == "category":
        writer.writerow(["category", "key", "value"])
        for key, data in results.items():
            if isinstance(data, dict):
                for k, v in flatten_dict(data).items():
                    writer.writerow([key, k, v])
            else:
                writer.writerow([key, "", data])
    elif mode == "file":
        writer.writerow(["file", "key", "value"])
        for file_path, data in results.items():
            findings = data.get("findings", {}) if isinstance(data, dict) else {}
            for key, value in flatten_dict(findings).items():
                writer.writerow([file_path, key, value])
    else:
        writer.writerow(["target", "type", "key", "value"])
        for target, data in results.items():
            if isinstance(data, dict) and "findings" in data:
                target_type = data.get("type", "unknown")
                for key, value in flatten_dict(data["findings"]).items():
                    writer.writerow([target, target_type, key, value])
            elif isinstance(data, dict):
                for key, value in flatten_dict(data).items():
                    writer.writerow([target, "unknown", key, value])
            else:
                writer.writerow([target, "unknown", "", data])

    return buf.getvalue().rstrip("\n")


def output_results(results: Dict[str, Any], args: argparse.Namespace, mode: str = "target") -> None:
    """Print results to stdout or save them to args.output in JSON/TXT/CSV format."""
    output_path = getattr(args, "output", None)
    fmt = getattr(args, "format", "json") or "json"

    if output_path:
        try:
            if fmt == "json":
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, default=str, ensure_ascii=False)
            elif fmt == "txt":
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(format_results_txt(results, mode=mode))
            elif fmt == "csv":
                with open(output_path, "w", encoding="utf-8", newline="") as f:
                    f.write(format_results_csv(results, mode=mode))
            print(f"\n{Colors.GREEN}[+] Results saved to {output_path}{Colors.RESET}")
        except OSError as e:
            print(f"\n{Colors.RED}[!] Failed to write {output_path}: {e}{Colors.RESET}")
    else:
        print(f"\n{Colors.CYAN}{'=' * 60}{Colors.RESET}")
        print(format_results_txt(results, mode=mode))
