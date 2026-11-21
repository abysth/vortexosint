"""
OSINT Module - General OSINT Reconnaissance
"""

import argparse
import concurrent.futures
import os
import re
import socket
import ssl
from typing import Dict, Any, List
from urllib.parse import urljoin

from vortexosint.core.colors import Colors
from vortexosint.core.banner import print_module_banner
from vortexosint.core.output import (
    flatten_dict as _flatten_dict,
    format_dict as _format_dict,
    format_results_csv as _format_results_csv,
    format_results_txt as _format_results_txt,
    output_results as _output_results,
)

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; VortexOSINT/1.0)"}

_DISPOSABLE_DOMAINS = {
    'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com',
    'temp-mail.org', 'yopmail.com', 'throwaway.email', 'trashmail.com',
    'sharklasers.com', 'getnada.com', 'dispostable.com', 'maildrop.cc',
}

_ROLE_ACCOUNTS = {
    'admin', 'administrator', 'support', 'info', 'contact', 'sales',
    'noreply', 'no-reply', 'postmaster', 'webmaster', 'security', 'abuse',
    'billing', 'help', 'hr', 'jobs', 'office', 'team',
}

_COUNTRY_CODES = {
    '1': ('United States / Canada', 'America/New_York'),
    '7': ('Russia / Kazakhstan', 'Europe/Moscow'),
    '20': ('Egypt', 'Africa/Cairo'),
    '27': ('South Africa', 'Africa/Johannesburg'),
    '30': ('Greece', 'Europe/Athens'),
    '31': ('Netherlands', 'Europe/Amsterdam'),
    '32': ('Belgium', 'Europe/Brussels'),
    '33': ('France', 'Europe/Paris'),
    '34': ('Spain', 'Europe/Madrid'),
    '39': ('Italy', 'Europe/Rome'),
    '41': ('Switzerland', 'Europe/Zurich'),
    '44': ('United Kingdom', 'Europe/London'),
    '48': ('Poland', 'Europe/Warsaw'),
    '49': ('Germany', 'Europe/Berlin'),
    '55': ('Brazil', 'America/Sao_Paulo'),
    '61': ('Australia', 'Australia/Sydney'),
    '81': ('Japan', 'Asia/Tokyo'),
    '86': ('China', 'Asia/Shanghai'),
    '90': ('Turkey', 'Europe/Istanbul'),
    '91': ('India', 'Asia/Kolkata'),
    '212': ('Morocco', 'Africa/Casablanca'),
    '213': ('Algeria', 'Africa/Algiers'),
    '216': ('Tunisia', 'Africa/Tunis'),
    '351': ('Portugal', 'Europe/Lisbon'),
    '380': ('Ukraine', 'Europe/Kyiv'),
}


def run(args: argparse.Namespace) -> int:
    """Run the OSINT module."""
    print_module_banner("OSINT", "General OSINT Reconnaissance & Information Gathering")

    targets = []
    if args.domain:
        targets.append(('domain', args.domain))
    if args.email:
        targets.append(('email', args.email))
    if args.phone:
        targets.append(('phone', args.phone))
    if args.username:
        targets.append(('username', args.username))
    if args.ip:
        targets.append(('ip', args.ip))

    if not targets:
        print(f"{Colors.RED}[!] No target specified. Use --domain, --email, --phone, --username, or --ip{Colors.RESET}")
        return 1

    results = {}

    for target_type, target_value in targets:
        print(f"\n{Colors.CYAN}[*] Investigating {target_type}: {Colors.BOLD}{target_value}{Colors.RESET}")
        result = investigate_target(target_type, target_value, args)
        results[target_value] = result

    output_results(results, args)
    return 0


def investigate_target(target_type: str, target_value: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate a single target based on type."""
    result = {
        'target': target_value,
        'type': target_type,
        'findings': {}
    }

    if target_type == 'domain':
        result['findings'] = investigate_domain(target_value, args)
    elif target_type == 'email':
        result['findings'] = investigate_email(target_value, args)
    elif target_type == 'phone':
        result['findings'] = investigate_phone(target_value, args)
    elif target_type == 'username':
        result['findings'] = investigate_username(target_value, args)
    elif target_type == 'ip':
        result['findings'] = investigate_ip(target_value, args)

    return result


def investigate_domain(domain: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate a domain."""
    clean = _clean_domain(domain)
    findings = {
        'whois': get_whois(clean),
        'dns': get_dns_records(clean),
        'subdomains': enumerate_subdomains(clean, args.deep),
        'ssl': get_ssl_info(clean),
        'technologies': detect_technologies(clean),
        'emails': find_emails(clean) if args.deep else [],
        'links': crawl_links(clean) if args.deep else [],
        'wayback': get_wayback_urls(clean, getattr(args, 'wayback_limit', 200),
                                    getattr(args, 'timeout', 30))
        if getattr(args, 'wayback', False) else {},
    }
    return findings


def investigate_email(email: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate an email address."""
    domain = email.split('@')[-1].strip() if '@' in email else ''
    mx = get_mx_records(domain) if domain else []
    findings = {
        'format_valid': validate_email_format(email),
        'domain': domain,
        'mx_records': mx,
        'breach_check': check_breaches(email) if args.deep else {},
        'gravatar': check_gravatar(email),
        'deliverability': check_deliverability(email, mx) if args.deep else {},
    }
    return findings


def investigate_phone(phone: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate a phone number."""
    parsed = parse_phone(phone)
    findings = {
        'format': parsed,
        'location': lookup_phone_location(phone),
        'line_type': detect_line_type(phone),
        'carrier': lookup_carrier(phone),
    }
    return findings


def investigate_username(username: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate a username across platforms concurrently."""
    from vortexosint.modules import social_module
    platforms = get_platforms(args.sources)
    return social_module.investigate_username(username, platforms)


def investigate_ip(ip: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate an IP address."""
    geo = get_ip_geolocation(ip)
    findings = {
        'geolocation': geo,
        'asn': get_asn_info(ip, geo),
        'reverse_dns': get_reverse_dns(ip),
        'ports': scan_common_ports(ip) if args.deep else [],
        'reputation': check_ip_reputation(ip),
        'vpn_proxy': detect_vpn_proxy(ip, geo),
    }
    return findings


def _clean_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    for prefix in ("http://", "https://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    return d.split("/")[0].split(":")[0]


WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"

INTERESTING_EXTS = {
    ".js", ".json", ".php", ".asp", ".aspx", ".jsp", ".env", ".bak",
    ".old", ".sql", ".xml", ".txt", ".pdf", ".zip", ".tar", ".gz",
    ".config", ".yml", ".yaml", ".log", ".swp",
}
INTERESTING_KEYS = ("admin", "login", "api", "config", "backup", "test",
                    "dev", "staging", "private", ".git/")


def get_wayback_urls(domain: str, limit: int = 200, timeout: int = 30) -> Dict[str, Any]:
    """Query the Wayback CDX API for archived URLs (HTTP 200, deduped)."""
    print(f"  {Colors.YELLOW}[~] Querying Wayback Machine CDX...{Colors.RESET}")
    try:
        import requests
    except ImportError:
        print(f"  {Colors.RED}[!] The 'requests' package is required{Colors.RESET}")
        return {'error': 'requests not installed', 'total': 0, 'urls': []}
    domain = _clean_domain(domain)
    if not domain:
        return {'error': 'empty domain', 'total': 0, 'urls': []}
    params = {"url": domain, "matchType": "domain", "output": "json",
              "filter": "statuscode:200", "collapse": "urlkey",
              "limit": str(max(1, limit))}
    try:
        resp = requests.get(WAYBACK_CDX, params=params, headers=_HEADERS, timeout=timeout)
        if resp.status_code != 200:
            print(f"  {Colors.RED}[!] Wayback API HTTP {resp.status_code}{Colors.RESET}")
            return {'error': f'http {resp.status_code}', 'total': 0, 'urls': []}
        rows = resp.json()
    except Exception as e:
        print(f"  {Colors.RED}[!] Wayback query failed: {e}{Colors.RESET}")
        return {'error': str(e), 'total': 0, 'urls': []}
    if not rows:
        return {'total': 0, 'urls': [], 'interesting': [], 'by_extension': {}}
    body = rows[1:] if rows[0][0] == "urlkey" else rows
    urls = [row[2] for row in body if len(row) >= 3 and row[2]]
    by_ext: Dict[str, int] = {}
    interesting = []
    for u in urls:
        path = u.split("?", 1)[0].lower()
        ext = os.path.splitext(path)[1] or "(none)"
        by_ext[ext] = by_ext.get(ext, 0) + 1
        if ext in INTERESTING_EXTS or any(k in path for k in INTERESTING_KEYS):
            interesting.append(u)
    interesting = interesting[:50]
    print(f"  {Colors.GREEN}[+] {len(urls)} archived URLs "
          f"({len(interesting)} interesting){Colors.RESET}")
    top_ext = dict(sorted(by_ext.items(), key=lambda kv: -kv[1])[:15])
    return {'total': len(urls), 'limit': limit, 'urls': urls,
            'interesting': interesting, 'by_extension': top_ext}


def show_wayback(data: Dict[str, Any], domain: str):
    """Pretty summary for quick mode."""
    if data.get('error'):
        print(f"{Colors.RED}[!] Wayback: {data['error']}{Colors.RESET}")
        return
    print(f"\n{Colors.CYAN}[*] Wayback Machine — {domain}: "
          f"{Colors.BOLD}{data['total']} URLs archivees{Colors.RESET}")
    if data.get('by_extension'):
        print(f"  {Colors.YELLOW}Top extensions:{Colors.RESET}")
        for ext, count in list(data['by_extension'].items())[:8]:
            print(f"    {ext}: {count}")
    if data.get('interesting'):
        print(f"  {Colors.YELLOW}Interessantes ({len(data['interesting'])}):{Colors.RESET}")
        for u in data['interesting'][:30]:
            print(f"    - {u}")
    else:
        print("  " + Colors.dim("Rien de suspect dans cet echantillon."))


# --- Real OSINT implementations ---

def _first_str(val: Any) -> str:
    if isinstance(val, list):
        return str(val[0]) if val else ''
    return str(val) if val is not None else ''


def get_whois(domain: str) -> Dict[str, Any]:
    """Get real WHOIS information using python-whois."""
    print(f"  {Colors.YELLOW}[~] Querying WHOIS...{Colors.RESET}")
    try:
        import whois  # type: ignore
        w = whois.whois(domain)
        ns = w.name_servers or []
        if isinstance(ns, (set, tuple)):
            ns = sorted(str(x).lower() for x in ns)
        elif isinstance(ns, list):
            ns = sorted({str(x).lower() for x in ns})
        else:
            ns = [str(ns).lower()] if ns else []
        return {
            'registrar': _first_str(w.registrar),
            'creation_date': _first_str(w.creation_date),
            'expiration_date': _first_str(w.expiration_date),
            'name_servers': ns,
            'status': w.status if isinstance(w.status, list) else ([w.status] if w.status else []),
            'org': _first_str(getattr(w, 'org', '')),
            'country': _first_str(getattr(w, 'country', '')),
        }
    except ImportError:
        return {'error': 'python-whois not installed'}
    except Exception as e:
        return {'error': str(e)}


def get_dns_records(domain: str) -> Dict[str, List[str]]:
    """Get real DNS records using dnspython."""
    print(f"  {Colors.YELLOW}[~] Querying DNS records...{Colors.RESET}")
    records: Dict[str, List[str]] = {}
    try:
        import dns.resolver  # type: ignore
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        for rtype in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'):
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [r.to_text() for r in answers]
            except Exception:
                records[rtype] = []
        return records
    except ImportError:
        # Minimal stdlib fallback for A/AAAA
        try:
            infos = socket.getaddrinfo(domain, None)
            a = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
            aaaa = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
            return {'A': a, 'AAAA': aaaa}
        except Exception as e:
            return {'error': [str(e)]}


def enumerate_subdomains(domain: str, deep: bool) -> List[str]:
    """Enumerate subdomains passively via crt.sh (+ optional DNS brute-force in deep mode)."""
    print(f"  {Colors.YELLOW}[~] Enumerating subdomains...{Colors.RESET}")
    found = set()

    # 1) Passive Certificate Transparency (crt.sh)
    try:
        import requests
        resp = requests.get(
            "https://crt.sh/",
            params={'q': f'%.{domain}', 'output': 'json'},
            headers=_HEADERS, timeout=15,
        )
        if resp.status_code == 200:
            for entry in resp.json():
                for name in str(entry.get('name_value', '')).splitlines():
                    name = name.strip().lower().lstrip('*.')
                    if name.endswith(f'.{domain}') and name != domain:
                        found.add(name)
    except Exception:
        pass

    # 2) Active DNS resolution of common prefixes when --deep
    if deep:
        prefixes = [
            'www', 'mail', 'ftp', 'api', 'dev', 'staging', 'admin', 'blog',
            'shop', 'app', 'test', 'beta', 'vpn', 'git', 'cdn', 'static',
            'portal', 'status', 'docs', 'sso', 'auth',
        ]
        # Skip brute-force if wildcard DNS resolves random nonexistent label
        wildcard = False
        try:
            socket.gethostbyname(f"vortex-nonexistent-9f8e7d.{domain}")
            wildcard = True
        except OSError:
            pass

        if not wildcard:
            def _probe(sub: str) -> str:
                host = f"{sub}.{domain}"
                try:
                    socket.getaddrinfo(host, None)
                    return host
                except OSError:
                    return ''

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                for host in pool.map(_probe, prefixes):
                    if host:
                        found.add(host)

    return sorted(found)[:100]


def get_ssl_info(domain: str) -> Dict[str, Any]:
    """Retrieve real TLS/SSL certificate details via stdlib ssl."""
    print(f"  {Colors.YELLOW}[~] Checking SSL certificate...{Colors.RESET}")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert() or {}
                cipher = ssock.cipher()
        issuer = dict(x[0] for x in cert.get('issuer', ()))
        subject = dict(x[0] for x in cert.get('subject', ()))
        sans = [v for k, v in cert.get('subjectAltName', ()) if k == 'DNS']
        return {
            'issuer': issuer.get('organizationName') or issuer.get('commonName', ''),
            'subject': subject.get('commonName', ''),
            'valid_from': cert.get('notBefore', ''),
            'valid_to': cert.get('notAfter', ''),
            'subject_alt_names': sans[:50],
            'tls_version': ssock.version() if hasattr(ssock, 'version') else '',
            'cipher': cipher[0] if cipher else '',
            'serial_number': cert.get('serialNumber', ''),
        }
    except Exception as e:
        return {'error': str(e)}


def detect_technologies(domain: str) -> List[Dict[str, str]]:
    """Detect web server, CDN, and frameworks from HTTP headers & HTML."""
    print(f"  {Colors.YELLOW}[~] Detecting technologies...{Colors.RESET}")
    try:
        import requests
    except ImportError:
        return []

    resp = None
    for scheme in ('https', 'http'):
        try:
            resp = requests.get(f"{scheme}://{domain}", headers=_HEADERS, timeout=10, allow_redirects=True)
            break
        except Exception:
            continue
    if resp is None:
        return []

    techs: List[Dict[str, str]] = []
    seen = set()

    def _add(name: str, category: str, version: str = ''):
        key = (name.lower(), category.lower())
        if key not in seen:
            seen.add(key)
            techs.append({'name': name, 'category': category, 'version': version})

    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    if 'server' in hdrs:
        _add(hdrs['server'], 'Web Server')
    if 'x-powered-by' in hdrs:
        _add(hdrs['x-powered-by'], 'Backend / Runtime')
    if 'cf-ray' in hdrs or 'cloudflare' in hdrs.get('server', '').lower():
        _add('Cloudflare', 'CDN / WAF')
    if 'x-amz-cf-id' in hdrs:
        _add('Amazon CloudFront', 'CDN')
    if 'x-vercel-id' in hdrs:
        _add('Vercel', 'Hosting / PaaS')
    if 'x-nf-request-id' in hdrs:
        _add('Netlify', 'Hosting / PaaS')
    if 'x-shopify-stage' in hdrs:
        _add('Shopify', 'E-commerce')

    body = resp.text[:100000].lower()
    html_signatures = [
        ('wp-content', 'WordPress', 'CMS'),
        ('__next_data__', 'Next.js', 'JavaScript Framework'),
        ('__nuxt__', 'Nuxt.js', 'JavaScript Framework'),
        ('react', 'React', 'JavaScript Framework'),
        ('vue', 'Vue.js', 'JavaScript Framework'),
        ('jquery', 'jQuery', 'JavaScript Library'),
        ('bootstrap', 'Bootstrap', 'CSS Framework'),
        ('tailwindcss', 'Tailwind CSS', 'CSS Framework'),
        ('googletagmanager.com', 'Google Tag Manager', 'Analytics'),
    ]
    for marker, name, cat in html_signatures:
        if marker in body:
            _add(name, cat)

    return techs


def find_emails(domain: str) -> List[str]:
    """Extract email addresses found on the domain's homepage."""
    print(f"  {Colors.YELLOW}[~] Searching for emails...{Colors.RESET}")
    try:
        import requests
    except ImportError:
        return []

    email_re = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    found = set()
    for path in ('/', '/contact', '/about'):
        try:
            resp = requests.get(f"https://{domain}{path}", headers=_HEADERS, timeout=8)
            if resp.status_code == 200:
                for m in email_re.findall(resp.text):
                    if not m.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp')):
                        found.add(m.lower())
        except Exception:
            continue
    return sorted(found)[:50]


def crawl_links(domain: str) -> List[str]:
    """Extract unique links from the domain's homepage."""
    print(f"  {Colors.YELLOW}[~] Crawling links...{Colors.RESET}")
    try:
        import requests
        from bs4 import BeautifulSoup  # type: ignore
    except ImportError:
        return []

    base_url = f"https://{domain}/"
    try:
        resp = requests.get(base_url, headers=_HEADERS, timeout=10)
        if resp.status_code != 200:
            return []
        soup = BeautifulSoup(resp.text, 'html.parser')
        links = set()
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if href and not href.startswith(('javascript:', 'mailto:', '#')):
                links.add(urljoin(base_url, href))
        return sorted(links)[:100]
    except Exception:
        return []


def validate_email_format(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email or ''))


def get_mx_records(domain: str) -> List[str]:
    """Get real MX records for domain using dnspython."""
    print(f"  {Colors.YELLOW}[~] Querying MX records...{Colors.RESET}")
    try:
        import dns.resolver  # type: ignore
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        answers = resolver.resolve(domain, 'MX')
        return sorted(r.to_text() for r in answers)
    except Exception:
        return []


def check_breaches(email: str) -> Dict[str, Any]:
    """Check if email appears in HaveIBeenPwned (requires HIBP_API_KEY)."""
    from vortexosint.modules import social_module
    return social_module.check_breaches(email)


def check_gravatar(email: str) -> Dict[str, Any]:
    """Check Gravatar for email."""
    from vortexosint.modules import social_module
    return social_module.check_gravatar(email)


def check_deliverability(email: str, mx_records: List[str] = None) -> Dict[str, Any]:
    """Evaluate email deliverability signals (format, MX, disposable, role account)."""
    print(f"  {Colors.YELLOW}[~] Checking deliverability...{Colors.RESET}")
    valid = validate_email_format(email)
    local, _, domain = (email or '').partition('@')
    domain_lower = domain.lower().strip()
    mx = mx_records if mx_records is not None else (get_mx_records(domain_lower) if domain_lower else [])
    disposable = domain_lower in _DISPOSABLE_DOMAINS
    role_account = local.lower().strip() in _ROLE_ACCOUNTS
    return {
        'deliverable': bool(valid and mx and not disposable),
        'has_mx': bool(mx),
        'disposable': disposable,
        'role_account': role_account,
    }


def parse_phone(phone: str) -> Dict[str, str]:
    """Parse phone number and identify international calling code."""
    raw = (phone or '').strip()
    digits = re.sub(r'\D', '', raw)
    cc = ''
    if raw.startswith('+') or raw.startswith('00'):
        d = digits[2:] if raw.startswith('00') else digits
        for length in (3, 2, 1):
            if d[:length] in _COUNTRY_CODES:
                cc = d[:length]
                national = d[length:]
                return {
                    'original': phone,
                    'digits': digits,
                    'country_code': f'+{cc}',
                    'national_number': national,
                }
    return {
        'original': phone,
        'digits': digits,
        'country_code': f'+{cc}' if cc else 'Unknown',
        'national_number': digits,
    }


def lookup_carrier(phone: str) -> str:
    """Carrier lookup requires an external HLR/Numverify API."""
    print(f"  {Colors.YELLOW}[~] Looking up carrier...{Colors.RESET}")
    return 'Unknown (requires external HLR/Numverify API)'


def lookup_phone_location(phone: str) -> Dict[str, str]:
    """Determine country and default timezone from calling code."""
    print(f"  {Colors.YELLOW}[~] Looking up location...{Colors.RESET}")
    parsed = parse_phone(phone)
    cc = parsed['country_code'].lstrip('+')
    country, tz = _COUNTRY_CODES.get(cc, ('Unknown', 'Unknown'))
    return {
        'country': country,
        'timezone': tz,
    }


def detect_line_type(phone: str) -> str:
    """Detect basic line type where numbering plan is unambiguous (e.g. FR)."""
    parsed = parse_phone(phone)
    if parsed['country_code'] == '+33':
        nat = parsed['national_number'].lstrip('0')
        if nat.startswith(('6', '7')):
            return 'mobile'
        if nat.startswith(('1', '2', '3', '4', '5')):
            return 'landline'
        if nat.startswith('9'):
            return 'voip'
    return 'unknown'


def get_platforms(sources: str) -> List[str]:
    """Get list of platforms to check."""
    from vortexosint.modules import social_module
    return social_module.get_platforms(sources)


def check_username_platform(username: str, platform: str) -> Dict[str, Any]:
    """Check username on a specific platform."""
    from vortexosint.modules import social_module
    return social_module.check_username_platform(username, platform)


def get_ip_geolocation(ip: str) -> Dict[str, Any]:
    """Get real IP geolocation via ip-api.com."""
    print(f"  {Colors.YELLOW}[~] Getting geolocation...{Colors.RESET}")
    try:
        import requests
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={'fields': 'status,message,country,countryCode,regionName,city,'
                              'lat,lon,timezone,isp,org,as,proxy,hosting,query'},
            headers=_HEADERS, timeout=10,
        )
        data = resp.json()
        if data.get('status') != 'success':
            return {'ip': ip, 'error': data.get('message', 'lookup failed')}
        return {
            'ip': data.get('query', ip),
            'country': data.get('country'),
            'country_code': data.get('countryCode'),
            'region': data.get('regionName'),
            'city': data.get('city'),
            'lat': data.get('lat'),
            'lon': data.get('lon'),
            'timezone': data.get('timezone'),
            'isp': data.get('isp'),
            'org': data.get('org'),
            'as': data.get('as'),
            'proxy': data.get('proxy'),
            'hosting': data.get('hosting'),
        }
    except Exception as e:
        return {'ip': ip, 'error': str(e)}


def get_asn_info(ip: str, geo: Dict[str, Any] = None) -> Dict[str, Any]:
    """Extract ASN info from geolocation data or BGPView."""
    print(f"  {Colors.YELLOW}[~] Getting ASN info...{Colors.RESET}")
    if geo and geo.get('as'):
        parts = str(geo['as']).split(' ', 1)
        return {
            'asn': parts[0],
            'name': parts[1] if len(parts) > 1 else geo.get('org', ''),
            'country': geo.get('country_code', ''),
        }
    return {'asn': 'Unknown', 'name': 'Unknown'}


def get_reverse_dns(ip: str) -> List[str]:
    """Get real reverse DNS (PTR) via socket.gethostbyaddr."""
    print(f"  {Colors.YELLOW}[~] Getting reverse DNS...{Colors.RESET}")
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
        return [host] + list(aliases)
    except Exception:
        return []


def scan_common_ports(ip: str) -> List[Dict[str, Any]]:
    """Scan common TCP ports concurrently using network_module.scan_port."""
    print(f"  {Colors.YELLOW}[~] Scanning common ports...{Colors.RESET}")
    from vortexosint.modules import network_module
    common = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(common)) as pool:
        results = list(pool.map(lambda p: network_module.scan_port(ip, p, 'connect'), common))
    return [r for r in results if r.get('state') == 'open']


def check_ip_reputation(ip: str) -> Dict[str, Any]:
    """Check IP reputation via AbuseIPDB if ABUSEIPDB_API_KEY is configured."""
    print(f"  {Colors.YELLOW}[~] Checking IP reputation...{Colors.RESET}")
    api_key = os.environ.get('ABUSEIPDB_API_KEY', '').strip()
    if not api_key:
        return {'status': 'unavailable', 'note': 'Set ABUSEIPDB_API_KEY in .env for AbuseIPDB checks.'}
    try:
        import requests
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            headers={'Key': api_key, 'Accept': 'application/json'},
            timeout=10,
        )
        if resp.status_code != 200:
            return {'error': f'AbuseIPDB HTTP {resp.status_code}'}
        d = resp.json().get('data', {})
        score = d.get('abuseConfidenceScore', 0)
        return {
            'abuse_score': score,
            'total_reports': d.get('totalReports', 0),
            'malicious': score >= 50,
            'suspicious': 15 <= score < 50,
            'is_tor': d.get('isTor', False),
        }
    except Exception as e:
        return {'error': str(e)}


def detect_vpn_proxy(ip: str, geo: Dict[str, Any] = None) -> Dict[str, Any]:
    """Report proxy/hosting flags from ip-api.com."""
    print(f"  {Colors.YELLOW}[~] Detecting VPN/Proxy...{Colors.RESET}")
    if geo and 'proxy' in geo:
        return {
            'proxy_or_vpn': bool(geo.get('proxy')),
            'hosting': bool(geo.get('hosting')),
        }
    return {'proxy_or_vpn': None, 'hosting': None}


def output_results(results: Dict[str, Any], args: argparse.Namespace):
    """Output results in specified format."""
    _output_results(results, args, mode="target")


def format_results_txt(results: Dict[str, Any]) -> str:
    """Format results as text."""
    return _format_results_txt(results, mode="target")


def format_results_csv(results: Dict[str, Any]) -> str:
    """Format results as CSV."""
    return _format_results_csv(results, mode="target")


def format_dict(d: Dict, indent: int = 0) -> str:
    """Format dictionary as indented text."""
    return _format_dict(d, indent=indent)


def flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """Flatten nested dictionary."""
    return _flatten_dict(d, parent_key=parent_key, sep=sep)
