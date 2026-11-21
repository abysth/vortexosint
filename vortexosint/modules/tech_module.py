"""
Tech Module - Web Technology Fingerprinter (Wappalyzer-lite).
Detects web servers, CDNs/WAFs, CMS/frameworks, JS libraries & analytics from headers, cookies & HTML.
"""

import argparse
import re
from typing import Any, Dict, List

from vortexosint.core.banner import print_module_banner
from vortexosint.core.colors import Colors
from vortexosint.core.output import output_results as _output_results

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; VortexOSINT/1.0)"}

HEADER_SIGNATURES = [
    ("Cloudflare", "CDN/WAF", "cf-ray", r".+"),
    ("Cloudflare", "CDN/WAF", "server", r"cloudflare"),
    ("Nginx", "Web Server", "server", r"nginx"),
    ("Apache", "Web Server", "server", r"apache"),
    ("Microsoft IIS", "Web Server", "server", r"microsoft-iis"),
    ("LiteSpeed", "Web Server", "server", r"litespeed"),
    ("Caddy", "Web Server", "server", r"caddy"),
    ("AWS CloudFront", "CDN/WAF", "x-amz-cf-id", r".+"),
    ("Fastly", "CDN/WAF", "x-served-by", r"cache-"),
    ("Vercel", "Hosting/CDN", "x-vercel-id", r".+"),
    ("Netlify", "Hosting/CDN", "x-nf-request-id", r".+"),
    ("PHP", "Language", "x-powered-by", r"php"),
    ("Express.js", "Framework", "x-powered-by", r"express"),
    ("ASP.NET", "Framework", "x-powered-by", r"asp\.net"),
    ("Next.js", "Framework", "x-powered-by", r"next\.js"),
]

HTML_SIGNATURES = [
    ("WordPress", "CMS", r"wp-content/|wp-includes/|name=[\"']generator[\"'][^>]*WordPress"),
    ("Drupal", "CMS", r"Drupal\.settings|/sites/default/files/"),
    ("Joomla", "CMS", r"/media/jui/|name=[\"']generator[\"'][^>]*Joomla"),
    ("Shopify", "E-commerce", r"cdn\.shopify\.com|Shopify\.theme"),
    ("Wix", "CMS", r"static\.wixstatic\.com|X-Wix-"),
    ("Next.js", "Framework", r"__NEXT_DATA__|/_next/static/"),
    ("Nuxt.js", "Framework", r"__NUXT__|/_nuxt/"),
    ("React", "JS Library", r"react-dom|data-reactroot|__REACT_DEVTOOLS"),
    ("Vue.js", "JS Library", r"data-v-[0-9a-f]{6,}|vue\.runtime"),
    ("Angular", "Framework", r"ng-version=|angular\.min\.js"),
    ("jQuery", "JS Library", r"jquery(?:\.min)?\.js"),
    ("Bootstrap", "CSS Framework", r"bootstrap(?:\.min)?\.(?:css|js)"),
    ("Tailwind CSS", "CSS Framework", r"tailwindcss|cdn\.tailwindcss\.com"),
    ("Google Analytics / GTM", "Analytics", r"googletagmanager\.com|google-analytics\.com|gtag\("),
    ("Cloudflare Turnstile / reCAPTCHA", "Security", r"google\.com/recaptcha|challenges\.cloudflare\.com"),
    ("Stripe", "Payments", r"js\.stripe\.com"),
    ("Sentry", "Monitoring", r"browser\.sentry-cdn\.com|sentry\.io"),
]


def _normalize_url(target: str) -> str:
    t = (target or "").strip()
    if not t.startswith(("http://", "https://")):
        return f"https://{t}"
    return t


def fingerprint_response(headers: Dict[str, str], html: str, cookies: List[str] = None) -> Dict[str, Any]:
    """Detect technologies from HTTP headers, cookies and HTML body."""
    lowered = {k.lower(): str(v) for k, v in headers.items()}
    detected: Dict[str, List[str]] = {}

    def _add(cat: str, name: str):
        detected.setdefault(cat, [])
        if name not in detected[cat]:
            detected[cat].append(name)

    for name, cat, hkey, pattern in HEADER_SIGNATURES:
        val = lowered.get(hkey, "")
        if val and re.search(pattern, val, re.IGNORECASE):
            _add(cat, name)

    for name, cat, pattern in HTML_SIGNATURES:
        if re.search(pattern, html or "", re.IGNORECASE):
            _add(cat, name)

    cookie_names = [c.lower() for c in (cookies or [])]
    if any("phpsessid" in c for c in cookie_names):
        _add("Language", "PHP")
    if any("csrftoken" in c or "sessionid" in c for c in cookie_names):
        _add("Framework", "Django (likely)")
    if any("laravel_session" in c for c in cookie_names):
        _add("Framework", "Laravel")
    if any("jsessionid" in c for c in cookie_names):
        _add("Language", "Java / JVM")

    title_m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:120] if title_m else ""
    gen_m = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        html or "",
        re.IGNORECASE,
    )

    total = sum(len(v) for v in detected.values())
    return {
        "page_title": title,
        "meta_generator": gen_m.group(1).strip() if gen_m else "",
        "technologies_count": total,
        "technologies": detected,
        "server_header": lowered.get("server", ""),
    }


def scan_tech(target: str, timeout: int = 12) -> Dict[str, Any]:
    """Fetch a URL and fingerprint its technology stack."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}

    url = _normalize_url(target)
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=timeout, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)}

    info = fingerprint_response(dict(resp.headers), resp.text[:250_000], list(resp.cookies.keys()))
    info["url"] = resp.url
    info["status_code"] = resp.status_code
    return info


def run(args: argparse.Namespace) -> int:
    """Run the Web Technology Fingerprinter module."""
    print_module_banner("TECH", "Web Technology Fingerprinter (Server, CDN, CMS & Frameworks)")
    target = getattr(args, "url", None)
    if not target:
        print(f"{Colors.RED}[!] No target specified. Use --url <domain_or_url>{Colors.RESET}")
        return 1

    print(f"\n{Colors.CYAN}[*] Fingerprinting stack for: {Colors.BOLD}{target}{Colors.RESET}")
    results = {target: {"target": target, "type": "tech", "findings": scan_tech(target, timeout=getattr(args, "timeout", 12) or 12)}}
    _output_results(results, args, mode="target")
    return 0
