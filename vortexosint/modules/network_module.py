"""
Network Module - Network Reconnaissance
"""

import argparse
import concurrent.futures
import ipaddress
import re
import shutil
import socket
import subprocess
import sys
from typing import Dict, Any, List
from vortexosint.core.colors import Colors
from vortexosint.core.banner import print_module_banner
from vortexosint.core.output import (
    flatten_dict,
    format_dict,
    format_results_csv as _format_results_csv,
    format_results_txt as _format_results_txt,
    output_results as _output_results,
)

_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9._:/-]+$")


def _is_safe_host(host: str) -> bool:
    """Reject empty hosts, leading dashes (CLI flag injection), or invalid chars."""
    if not host or host.startswith("-"):
        return False
    return bool(_SAFE_HOST_RE.match(host))


def run(args: argparse.Namespace) -> int:
    """Run the Network module."""
    print_module_banner("NETWORK", "Network Reconnaissance & Port Scanning")

    results = {}

    # Handle public IP lookup
    if getattr(args, "my_ip", False):
        print(f"\n{Colors.CYAN}[*] Resolving public IP...{Colors.RESET}")
        results['my_ip'] = show_my_ip()

    # Handle ICMP ping
    if getattr(args, "ping", None):
        print(f"\n{Colors.CYAN}[*] Pinging: {Colors.BOLD}{args.ping}{Colors.RESET}")
        results['ping'] = ping_host(args.ping)

    # Handle ASN lookup
    if getattr(args, "asn", None):
        print(f"\n{Colors.CYAN}[*] Looking up ASN: {Colors.BOLD}{args.asn}{Colors.RESET}")
        results['asn'] = lookup_asn(args.asn)

    # Handle target scanning
    if args.target:
        print(f"\n{Colors.CYAN}[*] Scanning target: {Colors.BOLD}{args.target}{Colors.RESET}")
        results['scan'] = scan_target(args.target, args)

    if not results:
        print(f"{Colors.RED}[!] Nothing to do. Use --target, --asn, --my-ip or --ping{Colors.RESET}")
        return 1

    # Output results
    output_results(results, args)
    return 0


def show_my_ip() -> Dict[str, Any]:
    """Display the machine's public IP via several providers."""
    try:
        import requests
    except ImportError:
        print(f"  {Colors.RED}[!] The 'requests' package is required{Colors.RESET}")
        return {'error': 'requests not installed'}

    endpoints = [
        ("https://api.ipify.org?format=json", "json"),
        ("https://ifconfig.me/ip", "text"),
        ("https://ident.me", "text"),
    ]
    for url, kind in endpoints:
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                continue
            ip = resp.json()["ip"].strip() if kind == "json" else resp.text.strip()
            if ip:
                print(f"  {Colors.GREEN}[+] Public IP: {Colors.BOLD}{ip}{Colors.RESET}")
                print(Colors.dim(f"    via {url}"))
                return {'ip': ip, 'source': url}
        except Exception:
            continue
    print(f"  {Colors.RED}[!] Could not resolve public IP (offline?){Colors.RESET}")
    return {'error': 'unreachable'}


def ping_host(host: str, count: int = 4) -> Dict[str, Any]:
    """ICMP ping using the system binary (no root needed)."""
    if not _is_safe_host(host):
        print(f"  {Colors.RED}[!] Invalid host: {host}{Colors.RESET}")
        return {'host': host, 'error': 'invalid host'}

    binary = shutil.which("ping")
    if not binary:
        print(f"  {Colors.RED}[!] No 'ping' binary found on this system{Colors.RESET}")
        return {'host': host, 'error': 'ping binary not found'}

    flag = "-n" if sys.platform.startswith("win") else "-c"
    print(f"  {Colors.YELLOW}[~] Pinging {host} x{count}...{Colors.RESET}")
    try:
        proc = subprocess.run([binary, flag, str(count), host],
                              capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        print(f"  {Colors.RED}[!] Ping timed out{Colors.RESET}")
        return {'host': host, 'error': 'timeout'}
    except Exception as e:
        print(f"  {Colors.RED}[!] Ping failed: {e}{Colors.RESET}")
        return {'host': host, 'error': str(e)}

    out = proc.stdout or ""
    loss, avg = None, None
    m = (re.search(r"(\d+)\s*%\s*(?:loss|perte|packet loss)", out, re.IGNORECASE)
         or re.search(r"perte[^\d]*(\d+)\s*%", out, re.IGNORECASE))
    if m:
        loss = int(m.group(1))
    m = re.search(r"(?:Average|Moyenne)\s*=\s*(\d+)\s*ms", out, re.IGNORECASE)
    if m:
        avg = float(m.group(1))
    else:
        m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)", out)
        if m:
            avg = float(m.group(2))

    result = {'host': host, 'sent': count, 'loss_percent': loss,
              'avg_ms': avg, 'reachable': proc.returncode == 0}
    if result['reachable']:
        detail = f"loss={loss}%" if loss is not None else "ok"
        if avg is not None:
            detail += f" avg={avg}ms"
        print(f"  {Colors.GREEN}[+] {host} reachable ({detail}){Colors.RESET}")
    else:
        print(f"  {Colors.RED}[!] {host} unreachable{Colors.RESET}")
    return result


def lookup_asn(asn: str) -> Dict[str, Any]:
    """Lookup ASN information via RDAP / BGPView APIs."""
    raw = (asn or "").strip().upper()
    num = raw[2:] if raw.startswith("AS") else raw
    if not num.isdigit():
        print(f"  {Colors.RED}[!] Invalid ASN format: {asn} (expected e.g. AS15169){Colors.RESET}")
        return {'asn': asn, 'error': 'invalid ASN format'}

    asn_label = f"AS{num}"
    try:
        import requests
    except ImportError:
        print(f"  {Colors.RED}[!] The 'requests' package is required{Colors.RESET}")
        return {'asn': asn_label, 'error': 'requests not installed'}

    # 1) Try BGPView API
    try:
        resp = requests.get(
            f"https://api.bgpview.io/asn/{num}",
            headers={"User-Agent": "VortexOSINT/1.0"},
            timeout=10,
        )
        if resp.status_code == 200:
            payload = resp.json().get("data") or {}
            if payload:
                info = {
                    'asn': asn_label,
                    'name': payload.get('name') or 'Unknown',
                    'description': payload.get('description_short') or '',
                    'country': payload.get('country_code') or 'Unknown',
                    'website': payload.get('website') or '',
                    'rir': (payload.get('rir_allocation') or {}).get('rir_name', ''),
                    'source': 'bgpview',
                }
                print(f"  {Colors.GREEN}[+] {asn_label}: {info['name']} ({info['country']}){Colors.RESET}")
                return info
    except Exception:
        pass

    # 2) Fallback: ARIN RDAP (redirects to the authoritative RIR)
    try:
        resp = requests.get(
            f"https://rdap.arin.net/registry/autnum/{num}",
            headers={"Accept": "application/rdap+json", "User-Agent": "VortexOSINT/1.0"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            info = {
                'asn': asn_label,
                'name': data.get('name') or data.get('handle') or 'Unknown',
                'handle': data.get('handle') or '',
                'country': data.get('country') or 'Unknown',
                'status': data.get('status') or [],
                'source': 'rdap',
            }
            print(f"  {Colors.GREEN}[+] {asn_label}: {info['name']} ({info['country']}){Colors.RESET}")
            return info
    except Exception as e:
        print(f"  {Colors.RED}[!] ASN lookup failed: {e}{Colors.RESET}")
        return {'asn': asn_label, 'error': str(e)}

    print(f"  {Colors.RED}[!] ASN {asn_label} not found or API unreachable{Colors.RESET}")
    return {'asn': asn_label, 'error': 'not found or unreachable'}


def _expand_targets(target: str, max_hosts: int = 256) -> List[str]:
    """Expand a single host/IP or CIDR notation into a list of target strings."""
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in net.hosts()] or [str(net.network_address)]
        if len(hosts) > max_hosts:
            print(
                f"  {Colors.YELLOW}[!] CIDR {target} has {len(hosts)} hosts — "
                f"limiting scan to first {max_hosts} hosts{Colors.RESET}"
            )
            return hosts[:max_hosts]
        return hosts
    return [target]


def _grab_banner(sock: socket.socket, host: str, port: int) -> str:
    """Attempt a short banner grab on an already-connected TCP socket."""
    sock.settimeout(1.0)
    try:
        data = sock.recv(1024)
        if data:
            return data.decode("utf-8", errors="replace").strip()[:200]
    except socket.timeout:
        pass
    except OSError:
        return ""

    # For common HTTP ports, send a minimal HEAD request
    if port in (80, 8000, 8080, 8888):
        try:
            req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii", errors="ignore")
            sock.sendall(req)
            data = sock.recv(1024)
            if data:
                first_lines = data.decode("utf-8", errors="replace").splitlines()[:3]
                return " | ".join(line.strip() for line in first_lines if line.strip())[:200]
        except OSError:
            pass
    return ""


def scan_target(target: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Scan target host or CIDR network concurrently."""
    if not _is_safe_host(target):
        print(f"  {Colors.RED}[!] Invalid target: {target}{Colors.RESET}")
        return {'target': target, 'error': 'invalid target'}

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"  {Colors.RED}[!] Invalid ports '{args.ports}': {e}{Colors.RESET}")
        return {'target': target, 'error': str(e)}

    try:
        hosts = _expand_targets(target)
    except ValueError as e:
        print(f"  {Colors.RED}[!] Invalid CIDR target '{target}': {e}{Colors.RESET}")
        return {'target': target, 'error': str(e)}

    grab = bool(getattr(args, "banner_grab", False) or getattr(args, "service_detect", False))
    scan_type = getattr(args, "scan_type", "connect")
    rate = max(1, int(getattr(args, "rate", 100) or 100))
    workers = min(100, rate, max(1, len(ports) * len(hosts)))

    findings: Dict[str, Any] = {
        'target': target,
        'hosts_scanned': len(hosts),
        'scan_type': scan_type,
        'effective_scan_type': 'unsupported' if scan_type == 'udp' else 'connect',
        'ports': ports,
        'results': [],
    }

    tasks = [(h, p) for h in hosts for p in ports]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_port, h, p, scan_type, grab) for h, p in tasks]
        for fut in futures:
            findings['results'].append(fut.result())

    if getattr(args, "os_detect", False):
        print(f"  {Colors.YELLOW}[~] Detecting OS...{Colors.RESET}")
        findings['os'] = detect_os(hosts[0])

    return findings


def parse_ports(ports_arg: str) -> List[int]:
    """Parse and validate port specification (1-65535)."""
    if not ports_arg or not ports_arg.strip():
        raise ValueError("empty port specification")

    spec = ports_arg.strip().lower()
    if spec == 'top100':
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
                1433, 1521, 1723, 2049, 2375, 3128, 3306, 3389, 5432, 5900, 5985, 6379, 7001,
                8000, 8080, 8443, 8888, 9000, 9090, 9200, 9443, 10000, 27017]
    if spec == 'top1000':
        return list(range(1, 1001))
    if spec == 'all':
        return list(range(1, 65536))

    seen = set()
    ports: List[int] = []
    for raw_part in spec.split(','):
        part = raw_part.strip()
        if not part:
            continue
        if '-' in part:
            pieces = part.split('-')
            if len(pieces) != 2:
                raise ValueError(f"malformed port range '{part}'")
            start, end = int(pieces[0]), int(pieces[1])
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"port range out of bounds (1-65535): '{part}'")
            for p in range(start, end + 1):
                if p not in seen:
                    seen.add(p)
                    ports.append(p)
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"port out of bounds (1-65535): {p}")
            if p not in seen:
                seen.add(p)
                ports.append(p)

    if not ports:
        raise ValueError("no valid ports found")
    return ports


def scan_port(target: str, port: int, scan_type: str, banner_grab: bool = False) -> Dict[str, Any]:
    """TCP connect scan (stdlib, no root needed). Honest states only."""
    if scan_type == 'udp':
        return {'host': target, 'port': port, 'protocol': 'udp', 'state': 'unsupported',
                'service': get_service_name(port),
                'note': 'UDP scan supprimé (résultats factices avant)'}

    banner = ""
    try:
        with socket.create_connection((target, port), timeout=1.5) as sock:
            state = 'open'
            if banner_grab:
                banner = _grab_banner(sock, target, port)
    except socket.timeout:
        state = 'filtered'
    except (ConnectionRefusedError, OSError):
        state = 'closed'

    entry: Dict[str, Any] = {
        'host': target,
        'port': port,
        'protocol': 'tcp',
        'state': state,
        'service': get_service_name(port),
    }
    if banner:
        entry['banner'] = banner
    return entry


def get_service_name(port: int) -> str:
    """Get service name for port."""
    services = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn',
        143: 'imap', 443: 'https', 445: 'microsoft-ds', 465: 'smtps', 587: 'submission',
        993: 'imaps', 995: 'pop3s', 1433: 'ms-sql-s', 1521: 'oracle', 1723: 'pptp',
        2049: 'nfs', 2375: 'docker', 3128: 'squid', 3306: 'mysql', 3389: 'rdp',
        5432: 'postgresql', 5900: 'vnc', 5985: 'winrm', 6379: 'redis', 7001: 'weblogic',
        8000: 'http-alt', 8080: 'http-proxy', 8443: 'https-alt', 8888: 'sun-answerbook',
        9000: 'cslistener', 9090: 'zeus-admin', 9200: 'elasticsearch', 9443: 'https-alt2',
        10000: 'ndmp', 27017: 'mongodb',
    }
    return services.get(port, 'unknown')


def detect_os(target: str) -> Dict[str, Any]:
    """Detect OS via nmap (if available) else TTL heuristic.

    No more hardcoded result: returns 'Unknown' when it cannot tell,
    with a low/honest accuracy. Note: scanning a public IP usually
    fingerprints the ISP router/box (Linux-based), not the PC behind NAT.
    """
    if not _is_safe_host(target):
        return {'name': 'Unknown', 'version': '', 'accuracy': 0,
                'details': 'Invalid target host', 'method': 'none'}

    # 1) Try nmap -O if installed (needs privileges for full accuracy)
    nmap_bin = shutil.which("nmap")
    if nmap_bin:
        try:
            proc = subprocess.run(
                [nmap_bin, "-O", "-F", target],
                capture_output=True, text=True, timeout=90,
            )
            out = (proc.stdout or "") + "\n" + (proc.stderr or "")
            # Parse "Running: ...", "OS details: ...", "Aggressive OS guesses:"
            running = re.search(r"Running:\s*(.+)", out)
            details = re.search(r"OS details:\s*(.+)", out)
            guess = re.search(r"Aggressive OS guesses:\s*\n((?:.*\n){1,3})", out)
            if running or details:
                name = (running.group(1).strip() if running else details.group(1).strip())
                acc_m = re.search(r"(\d{1,3})%", out)
                acc = int(acc_m.group(1)) if acc_m else 70
                print(f"  {Colors.GREEN}[+] OS (nmap): {name}{Colors.RESET}")
                return {
                    'name': name,
                    'version': '',
                    'accuracy': acc,
                    'details': details.group(1).strip() if details else '',
                    'method': 'nmap',
                    'raw_guess': guess.group(1).strip() if guess else '',
                }
        except Exception as e:
            print(Colors.dim(f"    nmap failed ({e}), falling back to TTL"))
        else:
            # nmap ran but found nothing usable -> fall through to TTL
            if "Too many fingerprints" in out or "No OS matches" in out:
                print(Colors.dim("    nmap: no OS match, falling back to TTL"))

    # 2) TTL heuristic via ping (works without root)
    ping_bin = shutil.which("ping")
    ttl = None
    if ping_bin:
        flag = "-n" if sys.platform.startswith("win") else "-c"
        try:
            proc = subprocess.run(
                [ping_bin, flag, "2", target],
                capture_output=True, text=True, timeout=30,
            )
            m = re.search(r"ttl[=\s:]+(\d+)", proc.stdout or "", re.IGNORECASE)
            if m:
                ttl = int(m.group(1))
        except Exception:
            pass

    if ttl is None:
        # 3) Last resort: TCP hints are unreliable here, be honest
        try:
            socket.gethostbyname(target)
            reachable = True
        except Exception:
            reachable = False
        print(f"  {Colors.YELLOW}[~] OS inconnnu (hote injoignable ou TTL masque){Colors.RESET}")
        return {
            'name': 'Unknown',
            'version': '',
            'accuracy': 0,
            'details': 'Hote injoignable en ICMP et nmap indisponible/sans resultat. '
                       'Si tu scannes ton IP publique, tu fingerprintes ta box (Linux), pas ton PC.',
            'method': 'none',
            'reachable': reachable,
        }

    if ttl <= 64:
        guess_name, initial, acc = "Linux/Unix", 64, 65
    elif ttl <= 128:
        guess_name, initial, acc = "Windows", 128, 65
    else:
        guess_name, initial, acc = "Network device (Cisco/Solaris?)", 255, 50

    hops = initial - ttl
    print(f"  {Colors.GREEN}[+] OS probable (TTL={ttl}): {guess_name}{Colors.RESET}")
    print(Colors.dim(
        f"    TTL observe={ttl}, TTL initial suppose={initial} (~{hops} sauts). "
        f"Heuristique fragile derriere NAT/box/VPN."
    ))
    return {
        'name': guess_name,
        'version': '',
        'accuracy': acc,
        'details': f'TTL={ttl} (initial guess {initial}, ~{hops} hops)',
        'method': 'ttl',
        'ttl': ttl,
    }


def output_results(results: Dict[str, Any], args: argparse.Namespace):
    """Output results in specified format."""
    _output_results(results, args, mode="category")


def format_results_txt(results: Dict[str, Any]) -> str:
    """Format results as text."""
    return _format_results_txt(results, mode="category")


def format_results_csv(results: Dict[str, Any]) -> str:
    """Format results as CSV."""
    return _format_results_csv(results, mode="category")