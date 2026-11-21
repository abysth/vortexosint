"""
GEOSINT Module - Geospatial Intelligence
"""

import argparse
import math
import os
import urllib.parse
from typing import Dict, Any, List, Tuple

from vortexosint.core.colors import Colors
from vortexosint.core.banner import print_module_banner
from vortexosint.core.output import (
    flatten_dict as _flatten_dict,
    format_dict as _format_dict,
    format_results_csv as _format_results_csv,
    format_results_txt as _format_results_txt,
    output_results as _output_results,
)

_HEADERS = {"User-Agent": "VortexOSINT/1.0 (https://github.com/abysth/vortexosint)"}

_MCC_COUNTRIES = {
    '208': 'France', '310': 'United States', '311': 'United States',
    '234': 'United Kingdom', '262': 'Germany', '214': 'Spain',
    '222': 'Italy', '206': 'Belgium', '228': 'Switzerland',
    '204': 'Netherlands', '268': 'Portugal', '302': 'Canada',
    '440': 'Japan', '460': 'China', '404': 'India', '724': 'Brazil',
    '505': 'Australia', '604': 'Morocco', '603': 'Algeria', '605': 'Tunisia',
}

_LOCAL_OUI = {
    '00-1A-2B': 'Cisco Systems', '00-50-56': 'VMware', '00-0C-29': 'VMware',
    '00-1B-21': 'Intel', '00-23-32': 'Apple', '00-25-00': 'Apple',
    '3C-07-54': 'Apple', 'A4-83-E7': 'Apple',
    'DC-A6-32': 'Raspberry Pi Foundation', 'B8-27-EB': 'Raspberry Pi Foundation',
}


def run(args: argparse.Namespace) -> int:
    """Run the GEOSINT module."""
    print_module_banner("GEOSINT", "Geospatial Intelligence & Location Analysis")

    targets = []
    if args.ip:
        targets.append(('ip', args.ip))
    if args.coords:
        targets.append(('coords', args.coords))
    if args.address:
        targets.append(('address', args.address))
    if args.wifi:
        targets.append(('wifi', args.wifi))
    if args.cell:
        targets.append(('cell', args.cell))

    if not targets:
        print(f"{Colors.RED}[!] No target specified. Use --ip, --coords, --address, --wifi, or --cell{Colors.RESET}")
        return 1

    results = {}

    for target_type, target_value in targets:
        print(f"\n{Colors.CYAN}[*] Analyzing {target_type}: {Colors.BOLD}{target_value}{Colors.RESET}")
        result = analyze_target(target_type, target_value, args)
        results[target_value] = result

    output_results(results, args)

    if args.map:
        generate_map(results, args)

    return 0


def analyze_target(target_type: str, target_value: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Analyze a single target based on type."""
    result = {
        'target': target_value,
        'type': target_type,
        'findings': {}
    }

    if target_type == 'ip':
        result['findings'] = analyze_ip(target_value, args)
    elif target_type == 'coords':
        result['findings'] = analyze_coords(target_value, args)
    elif target_type == 'address':
        result['findings'] = analyze_address(target_value, args)
    elif target_type == 'wifi':
        result['findings'] = analyze_wifi(target_value, args)
    elif target_type == 'cell':
        result['findings'] = analyze_cell(target_value, args)

    return result


def analyze_ip(ip: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Analyze IP for geolocation."""
    findings = {}
    providers = get_providers(args.provider)
    for provider in providers:
        findings[provider] = get_geolocation(ip, provider)
    return findings


def analyze_coords(coords: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Analyze coordinates (reverse geocoding)."""
    try:
        lat, lon = map(float, coords.split(','))
        if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
            raise ValueError("out of range")
    except ValueError:
        return {'error': 'Invalid coordinates format. Use "lat,lon" (-90..90, -180..180)'}

    findings = {
        'coordinates': {'lat': lat, 'lon': lon},
        'reverse_geocoding': reverse_geocode(lat, lon),
        'nearby': find_nearby(lat, lon, args.radius),
        'map_link': f"https://maps.google.com/?q={lat},{lon}",
    }
    return findings


def analyze_address(address: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Analyze address (forward geocoding)."""
    encoded = urllib.parse.quote_plus(address)
    findings = {
        'address': address,
        'geocoding': geocode_address(address),
        'map_link': f"https://maps.google.com/?q={encoded}",
    }
    return findings


def analyze_wifi(bssid: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Analyze WiFi BSSID (wardriving lookup)."""
    findings = {
        'bssid': bssid,
        'vendor': lookup_oui(bssid),
        'location': lookup_wifi_location(bssid),
        'encryption': detect_wifi_encryption(bssid),
    }
    return findings


def analyze_cell(cell_info: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Analyze cell tower info."""
    parts = [p.strip() for p in cell_info.split(',')]
    if len(parts) < 4:
        return {'error': 'Invalid cell format. Use "MCC,MNC,LAC,CID"'}
    mcc, mnc, lac, cid = parts[:4]

    findings = {
        'mcc': mcc,
        'mnc': mnc,
        'lac': lac,
        'cid': cid,
        'operator': lookup_operator(mcc, mnc),
        'location': lookup_cell_location(mcc, mnc, lac, cid),
    }
    return findings


# --- Real provider implementations ---

def get_providers(provider_arg: str) -> List[str]:
    """Get list of geolocation providers."""
    all_providers = ['ipapi', 'ipinfo', 'geojs']
    if provider_arg == 'all':
        return all_providers
    return [provider_arg]


def get_geolocation(ip: str, provider: str) -> Dict[str, Any]:
    """Query real geolocation data from ip-api, ipinfo, or geojs."""
    print(f"  {Colors.YELLOW}[~] Querying {provider}...{Colors.RESET}")
    try:
        import requests
    except ImportError:
        return {'ip': ip, 'error': 'requests not installed'}

    try:
        if provider == 'ipapi':
            resp = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={'fields': 'status,message,country,countryCode,region,regionName,'
                                  'city,lat,lon,timezone,isp,org,as,query'},
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
                'region_code': data.get('region'),
                'city': data.get('city'),
                'lat': data.get('lat'),
                'lon': data.get('lon'),
                'timezone': data.get('timezone'),
                'isp': data.get('isp'),
                'org': data.get('org'),
                'asn': data.get('as'),
            }

        if provider == 'ipinfo':
            token = os.environ.get('IPINFO_TOKEN', '').strip()
            params = {'token': token} if token else {}
            resp = requests.get(f"https://ipinfo.io/{ip}/json",
                                params=params, headers=_HEADERS, timeout=10)
            if resp.status_code != 200:
                return {'ip': ip, 'error': f'HTTP {resp.status_code}'}
            data = resp.json()
            loc = (data.get('loc') or '').split(',')
            lat = float(loc[0]) if len(loc) == 2 and loc[0] else None
            lon = float(loc[1]) if len(loc) == 2 and loc[1] else None
            return {
                'ip': data.get('ip', ip),
                'country_code': data.get('country'),
                'region': data.get('region'),
                'city': data.get('city'),
                'lat': lat,
                'lon': lon,
                'timezone': data.get('timezone'),
                'org': data.get('org'),
            }

        if provider == 'geojs':
            resp = requests.get(f"https://get.geojs.io/v1/ip/geo/{ip}.json",
                                headers=_HEADERS, timeout=10)
            if resp.status_code != 200:
                return {'ip': ip, 'error': f'HTTP {resp.status_code}'}
            data = resp.json()
            return {
                'ip': data.get('ip', ip),
                'country': data.get('country'),
                'country_code': data.get('country_code'),
                'region': data.get('region'),
                'city': data.get('city'),
                'lat': float(data['latitude']) if data.get('latitude') else None,
                'lon': float(data['longitude']) if data.get('longitude') else None,
                'timezone': data.get('timezone'),
                'org': data.get('organization_name'),
                'asn': data.get('asn'),
            }

        return {'ip': ip, 'error': f'Unknown provider: {provider}'}
    except Exception as e:
        return {'ip': ip, 'error': str(e)}


def reverse_geocode(lat: float, lon: float) -> Dict[str, Any]:
    """Reverse geocode coordinates using OpenStreetMap Nominatim."""
    print(f"  {Colors.YELLOW}[~] Reverse geocoding...{Colors.RESET}")
    try:
        import requests
        resp = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={'format': 'jsonv2', 'lat': lat, 'lon': lon},
            headers=_HEADERS, timeout=12,
        )
        if resp.status_code != 200:
            return {'error': f'HTTP {resp.status_code}'}
        data = resp.json()
        addr = data.get('address', {})
        return {
            'formatted_address': data.get('display_name', ''),
            'street': addr.get('road', ''),
            'city': addr.get('city') or addr.get('town') or addr.get('village') or '',
            'state': addr.get('state', ''),
            'postal_code': addr.get('postcode', ''),
            'country': addr.get('country', ''),
            'country_code': (addr.get('country_code') or '').upper(),
        }
    except Exception as e:
        return {'error': str(e)}


def geocode_address(address: str) -> Dict[str, Any]:
    """Forward geocode an address using OpenStreetMap Nominatim."""
    print(f"  {Colors.YELLOW}[~] Geocoding address...{Colors.RESET}")
    try:
        import requests
        resp = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={'format': 'jsonv2', 'q': address, 'limit': 1},
            headers=_HEADERS, timeout=12,
        )
        if resp.status_code != 200:
            return {'error': f'HTTP {resp.status_code}'}
        items = resp.json()
        if not items:
            return {'found': False, 'error': 'Address not found'}
        top = items[0]
        return {
            'found': True,
            'lat': float(top['lat']),
            'lon': float(top['lon']),
            'formatted_address': top.get('display_name', address),
            'type': top.get('type', ''),
        }
    except Exception as e:
        return {'error': str(e)}


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> int:
    """Return distance in meters between two WGS84 coordinates."""
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return int(round(2 * r * math.atan2(math.sqrt(a), math.sqrt(1 - a))))


def find_nearby(lat: float, lon: float, radius: int) -> List[Dict[str, Any]]:
    """Find nearby named POIs via OpenStreetMap Overpass API."""
    capped = max(50, min(int(radius or 1000), 5000))
    print(f"  {Colors.YELLOW}[~] Searching nearby places ({capped}m)...{Colors.RESET}")
    try:
        import requests
        query = (
            f'[out:json][timeout:10];'
            f'node(around:{capped},{lat},{lon})["name"]["amenity"];'
            f'out body 15;'
        )
        resp = requests.post(
            "https://overpass-api.de/api/interpreter",
            data={'data': query}, headers=_HEADERS, timeout=15,
        )
        if resp.status_code != 200:
            return []
        places = []
        for el in resp.json().get('elements', [])[:15]:
            tags = el.get('tags', {})
            elat, elon = el.get('lat'), el.get('lon')
            if elat is None or elon is None:
                continue
            places.append({
                'name': tags.get('name', 'Unknown'),
                'type': tags.get('amenity', 'poi'),
                'distance_m': _haversine_m(lat, lon, elat, elon),
                'lat': elat,
                'lon': elon,
            })
        places.sort(key=lambda p: p['distance_m'])
        return places
    except Exception:
        return []


def lookup_oui(bssid: str) -> str:
    """Lookup hardware vendor from MAC/BSSID via macvendors.com (with local fallback)."""
    print(f"  {Colors.YELLOW}[~] Looking up OUI...{Colors.RESET}")
    oui = bssid[:8].upper().replace(':', '-')
    try:
        import requests
        resp = requests.get(f"https://api.macvendors.com/{bssid}",
                            headers=_HEADERS, timeout=8)
        if resp.status_code == 200 and resp.text.strip():
            return resp.text.strip()
    except Exception:
        pass
    return _LOCAL_OUI.get(oui, 'Unknown Vendor')


def lookup_wifi_location(bssid: str) -> Dict[str, Any]:
    """Lookup WiFi BSSID in WiGLE if WIGLE_API_NAME and WIGLE_API_TOKEN are set."""
    print(f"  {Colors.YELLOW}[~] Checking wardriving databases...{Colors.RESET}")
    name = os.environ.get('WIGLE_API_NAME', '').strip()
    token = os.environ.get('WIGLE_API_TOKEN', '').strip()
    if not (name and token):
        return {
            'found': False,
            'lat': None,
            'lon': None,
            'note': 'Set WIGLE_API_NAME and WIGLE_API_TOKEN in .env for WiGLE lookup.',
        }
    try:
        import requests
        resp = requests.get(
            "https://api.wigle.net/api/v2/network/search",
            params={'netid': bssid},
            auth=(name, token),
            headers=_HEADERS, timeout=12,
        )
        if resp.status_code != 200:
            return {'found': False, 'error': f'WiGLE HTTP {resp.status_code}'}
        items = resp.json().get('results') or []
        if not items:
            return {'found': False, 'lat': None, 'lon': None}
        top = items[0]
        return {
            'found': True,
            'ssid': top.get('ssid'),
            'lat': top.get('trilat'),
            'lon': top.get('trilong'),
            'last_seen': top.get('lastupdt'),
            'encryption': top.get('encryption'),
            'source': 'wigle',
        }
    except Exception as e:
        return {'found': False, 'error': str(e)}


def detect_wifi_encryption(bssid: str) -> str:
    """Detect WiFi encryption type (cannot be inferred passively from BSSID alone)."""
    return 'Unknown (requires active scan or WiGLE result)'


def lookup_operator(mcc: str, mnc: str) -> Dict[str, str]:
    """Lookup country from MCC (Mobile Country Code)."""
    print(f"  {Colors.YELLOW}[~] Looking up operator MCC:{mcc} MNC:{mnc}...{Colors.RESET}")
    return {
        'mcc': mcc,
        'mnc': mnc,
        'country': _MCC_COUNTRIES.get(str(mcc).strip(), 'Unknown'),
    }


def lookup_cell_location(mcc: str, mnc: str, lac: str, cid: str) -> Dict[str, Any]:
    """Lookup cell tower location via OpenCelliD if OPENCELLID_API_KEY is configured."""
    print(f"  {Colors.YELLOW}[~] Looking up cell tower location...{Colors.RESET}")
    key = os.environ.get('OPENCELLID_API_KEY', '').strip()
    if not key:
        return {
            'found': False,
            'lat': None,
            'lon': None,
            'note': 'Set OPENCELLID_API_KEY in .env for OpenCelliD lookup.',
        }
    try:
        import requests
        resp = requests.get(
            "https://opencellid.org/cell/get",
            params={'key': key, 'mcc': mcc, 'mnc': mnc, 'lac': lac, 'cellid': cid, 'format': 'json'},
            headers=_HEADERS, timeout=12,
        )
        data = resp.json()
        if 'lat' in data and 'lon' in data:
            return {
                'found': True,
                'lat': data['lat'],
                'lon': data['lon'],
                'range': data.get('range'),
                'samples': data.get('samples', 0),
                'source': 'opencellid',
            }
        return {'found': False, 'error': data.get('error', 'not found')}
    except Exception as e:
        return {'found': False, 'error': str(e)}


def _extract_points(results: Dict[str, Any]) -> List[Tuple[float, float, str]]:
    """Collect (lat, lon, label) markers from GEOSINT results."""
    points: List[Tuple[float, float, str]] = []

    def _walk(obj: Any, label: str):
        if isinstance(obj, dict):
            lat, lon = obj.get('lat'), obj.get('lon')
            if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                points.append((float(lat), float(lon), label))
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    _walk(v, f"{label} ({k})")
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    name = item.get('name', label)
                    _walk(item, str(name))

    for target, data in results.items():
        _walk(data.get('findings', data) if isinstance(data, dict) else data, str(target))
    return points


def generate_map(results: Dict[str, Any], args: argparse.Namespace) -> str:
    """Generate interactive HTML map using folium."""
    print(f"\n{Colors.CYAN}[*] Generating interactive map...{Colors.RESET}")
    try:
        import folium  # type: ignore
    except ImportError:
        print(f"  {Colors.RED}[!] folium is required to generate maps (pip install folium){Colors.RESET}")
        return ''

    points = _extract_points(results)
    if not points:
        print(f"  {Colors.YELLOW}[!] No coordinates found to plot on map.{Colors.RESET}")
        return ''

    center = [points[0][0], points[0][1]]
    m = folium.Map(location=center, zoom_start=11)
    for lat, lon, label in points:
        folium.Marker([lat, lon], popup=label, tooltip=label).add_to(m)

    out = getattr(args, 'output', None)
    if out:
        base = os.path.splitext(out)[0]
        map_file = f"{base}_map.html"
    else:
        map_file = 'vortexosint_map.html'

    m.save(map_file)
    print(f"  {Colors.GREEN}[+] Map saved to {map_file} ({len(points)} marker(s)){Colors.RESET}")
    return map_file


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
