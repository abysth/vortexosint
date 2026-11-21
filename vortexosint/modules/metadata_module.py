"""
Metadata Module - File Metadata Extraction
"""

import argparse
import datetime
import hashlib
import mimetypes
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
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


def run(args: argparse.Namespace) -> int:
    """Run the Metadata module."""
    print_module_banner("METADATA", "File Metadata Extraction & Analysis")

    files = []

    if args.file:
        files.append(Path(args.file))
    if args.dir:
        dir_path = Path(args.dir)
        if dir_path.exists():
            if args.recursive:
                files.extend(dir_path.rglob('*'))
            else:
                files.extend(dir_path.glob('*'))
        else:
            print(f"{Colors.RED}[!] Directory not found: {args.dir}{Colors.RESET}")
            return 1

    if not files:
        print(f"{Colors.RED}[!] No files specified. Use --file or --dir{Colors.RESET}")
        return 1

    # Filter to only existing files
    files = [f for f in files if f.is_file()]

    if not files:
        print(f"{Colors.YELLOW}[!] No files found{Colors.RESET}")
        return 0

    print(f"\n{Colors.CYAN}[*] Analyzing {len(files)} file(s)...{Colors.RESET}")

    results = {}
    for file_path in files:
        print(f"\n{Colors.YELLOW}[~] Analyzing: {file_path}{Colors.RESET}")
        result = analyze_file(file_path, args)
        results[str(file_path)] = result

    output_results(results, args)
    return 0


def analyze_file(file_path: Path, args: argparse.Namespace) -> Dict[str, Any]:
    """Analyze a single file."""
    stat = file_path.stat()
    ext = file_path.suffix.lower()
    result = {
        'file': str(file_path),
        'size': stat.st_size,
        'modified': stat.st_mtime,
        'extension': ext,
        'mime_type': get_mime_type(file_path),
        'findings': {}
    }

    findings: Dict[str, Any] = {}

    # Basic file info
    findings['basic'] = get_basic_info(file_path)

    # EXIF data
    if args.exif or ext in ['.jpg', '.jpeg', '.tiff', '.tif', '.png', '.webp']:
        findings['exif'] = extract_exif(file_path)

    # GPS data
    if args.gps or ext in ['.jpg', '.jpeg', '.tiff', '.tif']:
        findings['gps'] = extract_gps(file_path)

    # Strings extraction
    if args.strings:
        findings['strings'] = extract_strings(file_path)

    # Hashes
    findings['hashes'] = calculate_hashes(file_path)

    # File-specific analysis
    if ext == '.pdf':
        findings['pdf'] = analyze_pdf(file_path)
    elif ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
        findings['office'] = analyze_office(file_path)

    result['findings'] = findings
    return result


def get_mime_type(file_path: Path) -> str:
    """Get MIME type of file."""
    mime, _ = mimetypes.guess_type(str(file_path))
    return mime or 'application/octet-stream'


def get_basic_info(file_path: Path) -> Dict[str, Any]:
    """Get basic file information."""
    stat = file_path.stat()
    return {
        'name': file_path.name,
        'path': str(file_path),
        'size': stat.st_size,
        'size_human': format_size(stat.st_size),
        'created': datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
        'modified': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
        'accessed': datetime.datetime.fromtimestamp(stat.st_atime).isoformat(),
        'extension': file_path.suffix,
        'mime_type': get_mime_type(file_path),
    }


def format_size(size: float) -> str:
    """Format file size human-readable."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def extract_exif(file_path: Path) -> Dict[str, Any]:
    """Extract EXIF data from an image using exifread or Pillow."""
    print(f"  {Colors.YELLOW}[~] Extracting EXIF...{Colors.RESET}")
    raw_tags: Dict[str, str] = {}

    # 1) Prefer exifread for comprehensive EXIF tags
    try:
        import exifread  # type: ignore
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
        for k, v in tags.items():
            if k not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                raw_tags[str(k)] = str(v)[:200]
    except ImportError:
        pass
    except Exception as e:
        return {'has_exif': False, 'error': str(e)}

    # 2) Fallback to Pillow if exifread found nothing or is unavailable
    if not raw_tags:
        try:
            from PIL import Image, ExifTags  # type: ignore
            with Image.open(file_path) as img:
                exif = img.getexif()
                if exif:
                    for tag_id, value in exif.items():
                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                        raw_tags[str(tag_name)] = str(value)[:200]
        except ImportError:
            if not raw_tags:
                return {'has_exif': False, 'error': 'Neither exifread nor Pillow is installed'}
        except Exception:
            pass

    if not raw_tags:
        return {'has_exif': False}

    def _pick(*keys: str) -> str:
        for key in keys:
            if key in raw_tags and raw_tags[key]:
                return raw_tags[key]
        return 'Unknown'

    return {
        'has_exif': True,
        'camera': {
            'make': _pick('Image Make', 'Make'),
            'model': _pick('Image Model', 'Model'),
            'software': _pick('Image Software', 'Software'),
        },
        'datetime': _pick('EXIF DateTimeOriginal', 'Image DateTime', 'DateTimeOriginal', 'DateTime'),
        'settings': {
            'aperture': _pick('EXIF FNumber', 'FNumber'),
            'shutter_speed': _pick('EXIF ExposureTime', 'ExposureTime'),
            'iso': _pick('EXIF ISOSpeedRatings', 'ISOSpeedRatings'),
            'focal_length': _pick('EXIF FocalLength', 'FocalLength'),
        },
        'tag_count': len(raw_tags),
        'raw_tags': dict(list(raw_tags.items())[:50]),
    }


def _dms_to_decimal(values: Any, ref: str) -> Optional[float]:
    """Convert EXIF GPS DMS rational list to signed decimal degrees."""
    try:
        def _to_float(x: Any) -> float:
            if hasattr(x, 'num') and hasattr(x, 'den'):
                return float(x.num) / float(x.den) if x.den else 0.0
            return float(x)

        deg = _to_float(values[0])
        minutes = _to_float(values[1])
        seconds = _to_float(values[2])
        dec = deg + (minutes / 60.0) + (seconds / 3600.0)
        if str(ref).strip().upper() in ('S', 'W'):
            dec = -dec
        return round(dec, 6)
    except Exception:
        return None


def extract_gps(file_path: Path) -> Dict[str, Any]:
    """Extract GPS coordinates from image EXIF metadata."""
    print(f"  {Colors.YELLOW}[~] Extracting GPS...{Colors.RESET}")
    empty = {
        'has_gps': False,
        'latitude': None,
        'longitude': None,
        'altitude': None,
        'map_link': None,
    }
    try:
        import exifread  # type: ignore
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
    except ImportError:
        empty['error'] = 'exifread not installed'
        return empty
    except Exception as e:
        empty['error'] = str(e)
        return empty

    lat_tag = tags.get('GPS GPSLatitude')
    lat_ref = tags.get('GPS GPSLatitudeRef')
    lon_tag = tags.get('GPS GPSLongitude')
    lon_ref = tags.get('GPS GPSLongitudeRef')

    if not (lat_tag and lat_ref and lon_tag and lon_ref):
        return empty

    lat = _dms_to_decimal(lat_tag.values, str(lat_ref))
    lon = _dms_to_decimal(lon_tag.values, str(lon_ref))
    if lat is None or lon is None:
        return empty

    alt = None
    alt_tag = tags.get('GPS GPSAltitude')
    if alt_tag and alt_tag.values:
        try:
            v = alt_tag.values[0]
            alt = round(float(v.num) / float(v.den), 2) if getattr(v, 'den', 0) else None
        except Exception:
            alt = None

    return {
        'has_gps': True,
        'latitude': lat,
        'longitude': lon,
        'altitude': alt,
        'map_link': f"https://maps.google.com/?q={lat},{lon}",
    }


def extract_strings(file_path: Path, min_len: int = 4, limit: int = 100) -> List[str]:
    """Extract printable ASCII strings from the first 1 MB of a file."""
    print(f"  {Colors.YELLOW}[~] Extracting strings...{Colors.RESET}")
    strings: List[str] = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read(1024 * 1024)
        current: List[str] = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    strings.append(''.join(current))
                    if len(strings) >= limit:
                        return strings
                current = []
        if len(current) >= min_len and len(strings) < limit:
            strings.append(''.join(current))
    except Exception:
        pass
    return strings


def calculate_hashes(file_path: Path) -> Dict[str, str]:
    """Calculate file hashes by streaming in chunks."""
    print(f"  {Colors.YELLOW}[~] Calculating hashes...{Colors.RESET}")
    algorithms = ['md5', 'sha1', 'sha256', 'sha512']
    hashers = {algo: hashlib.new(algo) for algo in algorithms}

    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                for h in hashers.values():
                    h.update(chunk)
        return {algo: h.hexdigest() for algo, h in hashers.items()}
    except Exception as e:
        return {'error': str(e)}


def analyze_pdf(file_path: Path) -> Dict[str, Any]:
    """Analyze PDF metadata using PyPDF2."""
    print(f"  {Colors.YELLOW}[~] Analyzing PDF...{Colors.RESET}")
    try:
        import PyPDF2  # type: ignore
    except ImportError:
        return {'error': 'PyPDF2 not installed'}

    try:
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            encrypted = bool(reader.is_encrypted)
            pages = 0 if encrypted else len(reader.pages)
            meta = reader.metadata or {}

            # Detect JavaScript or embedded files in trailer/root
            has_js = False
            embedded_files: List[str] = []
            try:
                root = reader.trailer.get('/Root', {})
                if hasattr(root, 'get_object'):
                    root = root.get_object()
                if isinstance(root, dict):
                    names = root.get('/Names')
                    if hasattr(names, 'get_object'):
                        names = names.get_object()
                    if isinstance(names, dict):
                        if '/JavaScript' in names:
                            has_js = True
                        ef = names.get('/EmbeddedFiles')
                        if hasattr(ef, 'get_object'):
                            ef = ef.get_object()
                        if isinstance(ef, dict) and '/Names' in ef:
                            ef_list = ef['/Names']
                            if hasattr(ef_list, 'get_object'):
                                ef_list = ef_list.get_object()
                            if isinstance(ef_list, list):
                                embedded_files = [str(ef_list[i]) for i in range(0, len(ef_list), 2)]
                    if '/OpenAction' in root:
                        oa = str(root.get('/OpenAction'))
                        if 'JavaScript' in oa or '/JS' in oa:
                            has_js = True
            except Exception:
                pass

            def _m(key: str) -> str:
                val = meta.get(key)
                return str(val) if val is not None else ''

            return {
                'pages': pages,
                'title': _m('/Title'),
                'author': _m('/Author'),
                'subject': _m('/Subject'),
                'creator': _m('/Creator'),
                'producer': _m('/Producer'),
                'creation_date': _m('/CreationDate'),
                'modification_date': _m('/ModDate'),
                'encrypted': encrypted,
                'javascript': has_js,
                'embedded_files': embedded_files,
            }
    except Exception as e:
        return {'error': str(e)}


def _analyze_ooxml_zip(file_path: Path) -> Dict[str, Any]:
    """Read core/app properties directly from an OOXML (.docx/.xlsx/.pptx) zip."""
    info: Dict[str, Any] = {
        'title': '',
        'author': '',
        'subject': '',
        'keywords': '',
        'comments': '',
        'created': '',
        'modified': '',
        'last_modified_by': '',
        'revision': '',
        'application': '',
    }
    with zipfile.ZipFile(file_path, 'r') as zf:
        if 'docProps/core.xml' in zf.namelist():
            root = ET.fromstring(zf.read('docProps/core.xml'))
            mapping = {
                'title': 'title',
                'creator': 'author',
                'subject': 'subject',
                'keywords': 'keywords',
                'description': 'comments',
                'created': 'created',
                'modified': 'modified',
                'lastModifiedBy': 'last_modified_by',
                'revision': 'revision',
            }
            for elem in root:
                tag = elem.tag.split('}')[-1]
                if tag in mapping and elem.text:
                    info[mapping[tag]] = elem.text.strip()
        if 'docProps/app.xml' in zf.namelist():
            root = ET.fromstring(zf.read('docProps/app.xml'))
            for elem in root:
                tag = elem.tag.split('}')[-1]
                if tag == 'Application' and elem.text:
                    info['application'] = elem.text.strip()
    return info


def analyze_office(file_path: Path) -> Dict[str, Any]:
    """Analyze Office document metadata (.docx, .xlsx, .pptx)."""
    print(f"  {Colors.YELLOW}[~] Analyzing Office document...{Colors.RESET}")
    ext = file_path.suffix.lower()

    if ext in ('.doc', '.xls', '.ppt'):
        return {'error': f'Legacy binary Office format ({ext}) not supported; convert to OOXML'}

    # Try OOXML XML parsing first (works for docx, xlsx, pptx with zero extra deps)
    try:
        if zipfile.is_zipfile(file_path):
            return _analyze_ooxml_zip(file_path)
    except Exception as e:
        return {'error': str(e)}

    return {'error': 'File is not a valid OOXML archive'}


def output_results(results: Dict[str, Any], args: argparse.Namespace):
    """Output results in specified format."""
    _output_results(results, args, mode="file")


def format_results_txt(results: Dict[str, Any]) -> str:
    """Format results as text."""
    return _format_results_txt(results, mode="file")


def format_results_csv(results: Dict[str, Any]) -> str:
    """Format results as CSV."""
    return _format_results_csv(results, mode="file")


def format_dict(d: Dict, indent: int = 0) -> str:
    """Format dictionary as indented text."""
    return _format_dict(d, indent=indent)


def flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """Flatten nested dictionary."""
    return _flatten_dict(d, parent_key=parent_key, sep=sep)
