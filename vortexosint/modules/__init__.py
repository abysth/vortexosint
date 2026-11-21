"""
VortexOSINT Modules Package.

Available modules:
- osint: General OSINT reconnaissance
- geosint: Geospatial intelligence
- network: Network reconnaissance
- crypto: Cryptocurrency intelligence
- social: Social media intelligence
- metadata: File metadata extraction
- password: Secure passwords, passphrases & audits
- web: Web security headers & well-known files audit
- emailsec: Email & DNS security (SPF/DMARC/DKIM/CAA/propagation)
- ioc: IOC extraction, defang/refang & threat intel
- dork: Google/GitHub/Shodan dork generator
- github: GitHub developer OSINT
- decode: Encoding, JWT, Hash-ID, Timestamp & CIDR toolkit
- report: HTML / Markdown report generator
"""

from vortexosint.modules import (
    osint_module,
    geosint_module,
    network_module,
    crypto_module,
    social_module,
    metadata_module,
    password_module,
    web_module,
    emailsec_module,
    ioc_module,
    dork_module,
    github_module,
    decode_module,
    report_module,
)

__all__ = [
    'osint_module',
    'geosint_module',
    'network_module',
    'crypto_module',
    'social_module',
    'metadata_module',
    'password_module',
    'web_module',
    'emailsec_module',
    'ioc_module',
    'dork_module',
    'github_module',
    'decode_module',
    'report_module',
]
