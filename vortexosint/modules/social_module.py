"""
Social Module - Social Media Intelligence
"""

import argparse
import concurrent.futures
import hashlib
import os
from typing import Dict, Any, List, Optional

from vortexosint.core.colors import Colors
from vortexosint.core.banner import print_module_banner
from vortexosint.core.output import (
    flatten_dict as _flatten_dict,
    format_dict as _format_dict,
    format_results_csv as _format_results_csv,
    format_results_txt as _format_results_txt,
    output_results as _output_results,
)

_USER_AGENT = "Mozilla/5.0 (compatible; VortexOSINT/1.0; +https://github.com/abysth/vortexosint)"

# Platform URL templates and optional "not found" text markers (for sites returning HTTP 200)
PLATFORM_SPECS: Dict[str, Dict[str, Any]] = {
    'github': {'url': 'https://github.com/{u}'},
    'gitlab': {'url': 'https://gitlab.com/{u}'},
    'bitbucket': {'url': 'https://bitbucket.org/{u}/'},
    'codepen': {'url': 'https://codepen.io/{u}'},
    'replit': {'url': 'https://replit.com/@{u}'},
    'dev.to': {'url': 'https://dev.to/{u}'},
    'hashnode': {'url': 'https://hashnode.com/@{u}'},
    'medium': {'url': 'https://medium.com/@{u}', 'not_found': ['404', 'page not found']},
    'hackernews': {'url': 'https://news.ycombinator.com/user?id={u}', 'not_found': ['no such user']},
    'twitter': {'url': 'https://x.com/{u}'},
    'instagram': {'url': 'https://www.instagram.com/{u}/'},
    'facebook': {'url': 'https://www.facebook.com/{u}'},
    'linkedin': {'url': 'https://www.linkedin.com/in/{u}'},
    'reddit': {'url': 'https://www.reddit.com/user/{u}/about.json', 'not_found': ['"error": 404']},
    'pinterest': {'url': 'https://www.pinterest.com/{u}/'},
    'tiktok': {'url': 'https://www.tiktok.com/@{u}'},
    'tumblr': {'url': 'https://{u}.tumblr.com/'},
    'vk': {'url': 'https://vk.com/{u}'},
    'youtube': {'url': 'https://www.youtube.com/@{u}'},
    'twitch': {'url': 'https://www.twitch.tv/{u}'},
    'vimeo': {'url': 'https://vimeo.com/{u}'},
    'dailymotion': {'url': 'https://www.dailymotion.com/{u}'},
    'soundcloud': {'url': 'https://soundcloud.com/{u}'},
    'spotify': {'url': 'https://open.spotify.com/user/{u}'},
    'bandcamp': {'url': 'https://{u}.bandcamp.com/'},
    'dribbble': {'url': 'https://dribbble.com/{u}'},
    'behance': {'url': 'https://www.behance.net/{u}'},
    'flickr': {'url': 'https://www.flickr.com/people/{u}/'},
    'deviantart': {'url': 'https://www.deviantart.com/{u}'},
    'artstation': {'url': 'https://www.artstation.com/{u}'},
    'telegram': {'url': 'https://t.me/{u}', 'not_found': ['if you have <strong>telegram</strong>, you can contact']},
    'steam': {'url': 'https://steamcommunity.com/id/{u}', 'not_found': ['the specified profile could not be found']},
    'itch.io': {'url': 'https://{u}.itch.io/'},
    'producthunt': {'url': 'https://www.producthunt.com/@{u}'},
    'patreon': {'url': 'https://www.patreon.com/{u}'},
    'ko-fi': {'url': 'https://ko-fi.com/{u}'},
    'buymeacoffee': {'url': 'https://www.buymeacoffee.com/{u}'},
    'substack': {'url': 'https://{u}.substack.com/'},
    'keybase': {'url': 'https://keybase.io/{u}'},
    'mastodon': {'url': 'https://mastodon.social/@{u}'},
    'stackoverflow': {'url': 'https://stackoverflow.com/users/{u}'},
    'sourceforge': {'url': 'https://sourceforge.net/u/{u}/profile/'},
}


def run(args: argparse.Namespace) -> int:
    """Run the Social module."""
    print_module_banner("SOCIAL", "Social Media Intelligence & Username Enumeration")

    targets = []
    if args.username:
        targets.append(('username', args.username))
    if args.email:
        targets.append(('email', args.email))
    if args.phone:
        targets.append(('phone', args.phone))

    if not targets:
        print(f"{Colors.RED}[!] No target specified. Use --username, --email, or --phone{Colors.RESET}")
        return 1

    results = {}

    for target_type, target_value in targets:
        print(f"\n{Colors.CYAN}[*] Investigating {target_type}: {Colors.BOLD}{target_value}{Colors.RESET}")
        result = investigate_target(target_type, target_value, args)
        results[target_value] = result

    # Check availability if requested
    if args.check_availability and args.username:
        results[f"{args.username} (availability)"] = {
            'target': args.username,
            'type': 'availability',
            'findings': check_availability(args.username, args),
        }

    output_results(results, args)
    return 0


def investigate_target(target_type: str, target_value: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate a single target based on type."""
    result = {
        'target': target_value,
        'type': target_type,
        'findings': {}
    }

    platforms = get_platforms(args.platforms)

    if target_type == 'username':
        result['findings'] = investigate_username(target_value, platforms)
    elif target_type == 'email':
        result['findings'] = investigate_email(target_value, platforms)
    elif target_type == 'phone':
        result['findings'] = investigate_phone(target_value, platforms)

    return result


def investigate_username(username: str, platforms: List[str]) -> Dict[str, Any]:
    """Investigate username across platforms concurrently."""
    findings: Dict[str, Any] = {
        'username': username,
        'platforms': {},
        'total_found': 0,
        'profiles': [],
    }

    workers = min(16, max(1, len(platforms)))
    print(f"  {Colors.YELLOW}[~] Checking {len(platforms)} platform(s)...{Colors.RESET}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {
            pool.submit(check_username_platform, username, p): p for p in platforms
        }
        for fut in concurrent.futures.as_completed(future_map):
            platform = future_map[fut]
            result = fut.result()
            findings['platforms'][platform] = result
            if result.get('found'):
                findings['total_found'] += 1
                findings['profiles'].append({
                    'platform': platform,
                    'url': result.get('url'),
                    'status_code': result.get('status_code'),
                })
                print(f"  {Colors.GREEN}[+] Found on {platform}: {result.get('url')}{Colors.RESET}")

    return findings


def investigate_email(email: str, platforms: List[str]) -> Dict[str, Any]:
    """Investigate email (Gravatar + HIBP breaches)."""
    findings: Dict[str, Any] = {
        'email': email,
        'gravatar': check_gravatar(email),
        'breaches': check_breaches(email),
        'note': 'Direct email lookup on third-party social networks requires authenticated APIs.',
    }
    return findings


def investigate_phone(phone: str, platforms: List[str]) -> Dict[str, Any]:
    """Investigate phone (honest reporting)."""
    return {
        'phone': phone,
        'total_found': 0,
        'note': 'Public unauthenticated phone-to-social lookup is not supported by platforms.',
    }


def check_availability(username: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Check username availability on platforms using real HTTP checks."""
    print(f"\n{Colors.CYAN}[*] Checking availability for: {Colors.BOLD}{username}{Colors.RESET}")
    platforms = get_platforms(args.platforms)
    availability: Dict[str, Any] = {}
    workers = min(16, max(1, len(platforms)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {
            pool.submit(check_username_platform, username, p): p for p in platforms
        }
        for fut in concurrent.futures.as_completed(future_map):
            platform = future_map[fut]
            res = fut.result()
            available: Optional[bool]
            if res.get('error'):
                available = None
            else:
                available = not bool(res.get('found'))
            availability[platform] = {
                'available': available,
                'url': res.get('url'),
                'status_code': res.get('status_code'),
            }

    return availability


def get_platforms(platforms_arg: str) -> List[str]:
    """Get list of platforms to check."""
    if platforms_arg == 'all':
        return list(PLATFORM_SPECS.keys())
    return [p.strip().lower() for p in platforms_arg.split(',') if p.strip()]


def build_platform_url(username: str, platform: str) -> str:
    """Return the profile URL for a given platform."""
    spec = PLATFORM_SPECS.get(platform.lower())
    if spec:
        return spec['url'].format(u=username)
    return f'https://{platform}.com/{username}'


def check_username_platform(username: str, platform: str, timeout: int = 8) -> Dict[str, Any]:
    """Check whether a username exists on a platform via HTTP."""
    url = build_platform_url(username, platform)
    spec = PLATFORM_SPECS.get(platform.lower(), {})
    try:
        import requests
    except ImportError:
        return {'platform': platform, 'url': url, 'found': False, 'error': 'requests not installed'}

    try:
        resp = requests.get(
            url,
            headers={'User-Agent': _USER_AGENT},
            timeout=timeout,
            allow_redirects=True,
        )
        status = resp.status_code
        found = False
        if status == 200:
            markers = spec.get('not_found') or []
            if markers:
                body_lower = resp.text[:40000].lower()
                found = not any(m in body_lower for m in markers)
            else:
                found = True
        elif status == 404:
            found = False

        return {
            'platform': platform,
            'url': url,
            'found': found,
            'status_code': status,
            'error': None,
        }
    except Exception as e:
        return {
            'platform': platform,
            'url': url,
            'found': False,
            'status_code': None,
            'error': str(e),
        }


def check_gravatar(email: str) -> Dict[str, Any]:
    """Check if a Gravatar profile exists for an email."""
    print(f"  {Colors.YELLOW}[~] Checking Gravatar...{Colors.RESET}")
    email_hash = hashlib.md5(email.lower().strip().encode('utf-8')).hexdigest()
    avatar_url = f'https://www.gravatar.com/avatar/{email_hash}'
    profile_url = f'https://www.gravatar.com/{email_hash}'
    exists = False
    error = None

    try:
        import requests
        resp = requests.head(f"{avatar_url}?d=404", headers={'User-Agent': _USER_AGENT}, timeout=8)
        exists = resp.status_code == 200
    except Exception as e:
        error = str(e)

    res: Dict[str, Any] = {
        'exists': exists,
        'profile_url': profile_url if exists else None,
        'avatar_url': avatar_url if exists else None,
    }
    if error:
        res['error'] = error
    return res


def check_breaches(email: str) -> Dict[str, Any]:
    """Check email in HaveIBeenPwned if HIBP_API_KEY is configured."""
    print(f"  {Colors.YELLOW}[~] Checking breach databases...{Colors.RESET}")
    api_key = os.environ.get('HIBP_API_KEY', '').strip()
    if not api_key:
        return {
            'breached': None,
            'breach_count': 0,
            'breaches': [],
            'note': 'Set HIBP_API_KEY in .env to query HaveIBeenPwned.',
        }
    try:
        import requests
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={'hibp-api-key': api_key, 'user-agent': 'VortexOSINT/1.0'},
            params={'truncateResponse': 'true'},
            timeout=15,
        )
        if resp.status_code == 404:
            return {'breached': False, 'breach_count': 0, 'breaches': []}
        if resp.status_code == 200:
            items = [b.get('Name', '') for b in resp.json()]
            return {'breached': bool(items), 'breach_count': len(items), 'breaches': items}
        return {'breached': None, 'error': f'HIBP HTTP {resp.status_code}', 'breaches': []}
    except Exception as e:
        return {'breached': None, 'error': str(e), 'breaches': []}


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
