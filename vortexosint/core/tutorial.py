"""
Interactive & CLI Tutorial + Environment Setup Checker for VortexOSINT (FR).
Covers prerequisites, installation, .env API keys, live environment check, and all 20 modules.
"""

import importlib.util
import os
import sys
from typing import Dict, List, Optional, Tuple

from vortexosint.core import ui

CORE_DEPS: List[Tuple[str, str, str]] = [
    ("requests", "requests", "Requetes HTTP/API (indispensable)"),
    ("rich", "rich", "Tableaux, panneaux et couleurs"),
    ("colorama", "colorama", "Couleurs ANSI sous Windows"),
    ("dotenv", "python-dotenv", "Chargement automatique du fichier .env"),
    ("dns", "dnspython", "Requetes DNS (dns, emailsec, osint)"),
    ("whois", "python-whois", "Requetes WHOIS (osint)"),
]

OPTIONAL_DEPS: List[Tuple[str, str, str]] = [
    ("PIL", "pillow", "Metadonnees & EXIF images (metadata)"),
    ("exifread", "exifread", "Extraction GPS/EXIF avancee (metadata)"),
    ("PyPDF2", "PyPDF2", "Metadonnees fichiers PDF (metadata)"),
    ("docx", "python-docx", "Metadonnees fichiers Word .docx (metadata)"),
    ("openpyxl", "openpyxl", "Metadonnees fichiers Excel .xlsx (metadata)"),
    ("folium", "folium", "Cartes HTML interactives (geosint --map)"),
    ("bs4", "beautifulsoup4", "Parsing HTML avance"),
]

OPTIONAL_ENV_KEYS: List[Tuple[str, str]] = [
    ("GITHUB_TOKEN", "Augmente la limite API GitHub (60 -> 5000 req/h)"),
    ("HIBP_API_KEY", "Active HaveIBeenPwned v3 en plus de XposedOrNot (breach)"),
    ("IPINFO_TOKEN", "Fournisseur ipinfo.io avec quota etendu (geosint)"),
    ("ETHERSCAN_API_KEY", "Requetes Ethereum/Etherscan (crypto)"),
    ("BLOCKCYPHER_TOKEN", "Quota etendu BTC/LTC/DOGE (crypto)"),
]

TUTORIALS: Dict[str, Dict[str, object]] = {
    "osint": {
        "title": "OSINT — Reconnaissance generale",
        "but": "Collecter des infos publiques sur un domaine, email, telephone, pseudo ou IP (WHOIS, DNS, Wayback).",
        "entree": "Un domaine (example.com), un email, un numero (+33...), un pseudo ou une IP.",
        "mode": "Internet requis",
        "prerequis": "requests, dnspython, python-whois (inclus de base)",
        "api_key": "Aucune obligatoire",
        "examples": [
            "vortexosint osint --domain example.com",
            "vortexosint osint --domain example.com --wayback --wayback-limit 200",
            "vortexosint osint --email contact@example.com --deep",
            "vortexosint osint --phone \"+33 6 12 34 56 78\"",
            "vortexosint osint --username johndoe",
        ],
        "tip": "Ajoute --deep pour une analyse plus poussee et -o rapport.json pour sauvegarder.",
    },
    "geosint": {
        "title": "GEOSINT — Geolocalisation",
        "but": "Localiser une IP, convertir coordonnees GPS <-> adresse, ou chercher un BSSID WiFi / antenne relais.",
        "entree": "Une IP (8.8.8.8), des coords (\"48.8566,2.3522\"), une adresse ou un BSSID WiFi.",
        "mode": "Internet requis",
        "prerequis": "requests (+ folium optionnel pour --map)",
        "api_key": "Aucune obligatoire (IPINFO_TOKEN optionnel)",
        "examples": [
            "vortexosint geosint --ip 8.8.8.8",
            "vortexosint geosint --coords \"48.8566,2.3522\"",
            "vortexosint geosint --address \"Tour Eiffel, Paris\" --map",
            "vortexosint geosint --wifi \"AA:BB:CC:DD:EE:FF\"",
        ],
        "tip": "L'option --map cree une carte interactive HTML que tu peux ouvrir dans ton navigateur.",
    },
    "social": {
        "title": "SOCIAL — Recherche sur les reseaux sociaux",
        "but": "Verifier si un pseudo existe sur 50+ plateformes, ou investiguer un email/telephone.",
        "entree": "Un pseudo (ex: johndoe), un email ou un numero de telephone.",
        "mode": "Internet requis",
        "prerequis": "requests (inclus de base)",
        "api_key": "Aucune obligatoire",
        "examples": [
            "vortexosint social --username johndoe",
            "vortexosint social --username johndoe --platforms github,reddit,twitter",
            "vortexosint social --email johndoe@example.com",
        ],
        "tip": "Utilise --platforms pour cibler 3-4 sites et obtenir un resultat beaucoup plus rapide.",
    },
    "github": {
        "title": "GITHUB — OSINT developpeur",
        "but": "Recuperer profil, organisations, repos populaires, cles SSH publiques et emails dans les commits.",
        "entree": "Un pseudo GitHub (ex: octocat).",
        "mode": "Internet requis",
        "prerequis": "requests (inclus de base)",
        "api_key": "Aucune obligatoire (GITHUB_TOKEN recommande si beaucoup de requetes)",
        "examples": [
            "vortexosint github --username octocat",
        ],
        "tip": "Sans GITHUB_TOKEN, GitHub limite a 60 requetes/heure par IP.",
    },
    "network": {
        "title": "NETWORK — Scan reseau & diagnostic",
        "but": "Afficher ton IP publique, pinger un hote, scanner des ports, detecter services/OS et interroger un ASN.",
        "entree": "Une IP/hote (ex: scanme.nmap.org), un CIDR ou un ASN (ex: AS15169).",
        "mode": "Reseau local ou Internet",
        "prerequis": "Base Python (droits admin uniquement pour --scan-type syn)",
        "api_key": "Aucune",
        "examples": [
            "vortexosint network --my-ip",
            "vortexosint network --ping 8.8.8.8",
            "vortexosint network --target scanme.nmap.org --ports 22,80,443",
            "vortexosint network --target example.com --service-detect --banner-grab",
            "vortexosint network --asn AS15169",
        ],
        "tip": "Utilise --scan-type connect si tu n'es pas administrateur.",
    },
    "web": {
        "title": "WEB — Audit de securite web",
        "but": "Noter les headers HTTP de securite (A a F), suivre les redirections et lire robots.txt / security.txt.",
        "entree": "Une URL ou un domaine (ex: https://example.com ou example.com).",
        "mode": "Internet requis",
        "prerequis": "requests (inclus de base)",
        "api_key": "Aucune",
        "examples": [
            "vortexosint web --url https://example.com",
            "vortexosint web --url example.com --headers --files",
        ],
        "tip": "Si tu ne mets aucun flag (--headers/--files/--redirects), les 3 sont lances automatiquement.",
    },
    "tech": {
        "title": "TECH — Fingerprinting de stack web",
        "but": "Detecter serveur web, CDN/WAF, CMS (WordPress, Shopify...), frameworks JS/CSS et cookies.",
        "entree": "Une URL ou un domaine (ex: https://example.com).",
        "mode": "Internet requis",
        "prerequis": "requests (inclus de base)",
        "api_key": "Aucune",
        "examples": [
            "vortexosint tech --url https://example.com",
        ],
        "tip": "Combine-le avec `web` et `ssl` pour un profil complet d'un site web.",
    },
    "ssl": {
        "title": "SSL — Certificats TLS & crt.sh",
        "but": "Inspecter le certificat TLS en direct (expiration, SANs, empreinte SHA-256) et les logs crt.sh.",
        "entree": "Un nom de domaine (ex: example.com), port optionnel (defaut 443).",
        "mode": "Internet requis",
        "prerequis": "Base Python (+ requests pour --ct)",
        "api_key": "Aucune",
        "examples": [
            "vortexosint ssl --host example.com",
            "vortexosint ssl --host example.com --ct",
            "vortexosint ssl --host example.com --port 8443",
        ],
        "tip": "--ct decouvre souvent des sous-domaines via l'historique public des certificats.",
    },
    "dns": {
        "title": "DNS — Enregistrements, PTR & sous-domaines",
        "but": "Lister tous les records DNS (A, AAAA, MX, NS, TXT, CAA...), faire un Reverse DNS ou trouver des sous-domaines.",
        "entree": "Un domaine (example.com) ou une IP pour --reverse.",
        "mode": "Internet requis",
        "prerequis": "dnspython (+ requests pour --subdomains)",
        "api_key": "Aucune",
        "examples": [
            "vortexosint dns --domain example.com",
            "vortexosint dns --domain example.com --subdomains",
            "vortexosint dns --reverse 8.8.8.8",
        ],
        "tip": "--subdomains est 100% passif (crt.sh + HackerTarget), il ne touche pas le serveur cible.",
    },
    "emailsec": {
        "title": "EMAILSEC — Securite email (SPF/DMARC/DKIM)",
        "but": "Auditer la protection anti-spoofing d'un domaine (SPF, DMARC, DKIM, CAA) et la propagation DNS.",
        "entree": "Un nom de domaine (ex: example.com).",
        "mode": "Internet requis",
        "prerequis": "dnspython (inclus de base)",
        "api_key": "Aucune",
        "examples": [
            "vortexosint emailsec --domain example.com",
            "vortexosint emailsec --domain example.com --propagation",
            "vortexosint emailsec --domain example.com --selectors google,selector1",
        ],
        "tip": "Un domaine sans DMARC p=reject ou SPF -all peut etre usurpe par phishing.",
    },
    "mac": {
        "title": "MAC — Constructeur OUI & MAC aleatoire",
        "but": "Normaliser une adresse MAC, detecter si elle est randomisee/spoofee et identifier le fabricant.",
        "entree": "Une adresse MAC (00:11:22:33:44:55, 00-11-22-33-44-55 ou 0011.2233.4455).",
        "mode": "Hybride (base locale hors-ligne + fallback internet)",
        "prerequis": "Aucun (requests pour fallback macvendors.com)",
        "api_key": "Aucune",
        "examples": [
            "vortexosint mac --mac B8:27:EB:11:22:33",
            "vortexosint mac --mac 02-11-22-33-44-55 --offline",
        ],
        "tip": "Ajoute --offline pour ne faire aucune requete externe.",
    },
    "ioc": {
        "title": "IOC — Extraction, Defang & Threat Intel",
        "but": "Extraire IPs/URLs/emails/hashes d'un fichier ou texte, defang/refang des liens et verifier des IOC.",
        "entree": "Un chemin de fichier log/txt, un texte brut, une URL ou un hash.",
        "mode": "Hors-ligne (--extract/--defang/--refang) | Internet (--check)",
        "prerequis": "Base Python (+ requests pour --check)",
        "api_key": "Aucune",
        "examples": [
            "vortexosint ioc --extract alert.log",
            "vortexosint ioc --defang https://evil.com/login",
            "vortexosint ioc --refang hxxps://evil[.]com",
            "vortexosint ioc --check d41d8cd98f00b204e9800998ecf8427e",
        ],
        "tip": "Toujours utiliser --defang avant de coller un lien malveillant dans un rapport.",
    },
    "url": {
        "title": "URL — Unshortener & Anti-Phishing",
        "but": "Derouler une URL raccourcie (bit.ly...), nettoyer les trackers (utm_*, fbclid) et scorer le risque phishing.",
        "entree": "Une URL complete (ex: https://bit.ly/exemple).",
        "mode": "Hors-ligne (--phishing seul) | Internet (--expand)",
        "prerequis": "Base Python (+ requests pour --expand)",
        "api_key": "Aucune",
        "examples": [
            "vortexosint url --url https://bit.ly/exemple",
            "vortexosint url --url \"http://192.168.1.1/login-verify\" --phishing",
        ],
        "tip": "Lance --phishing seul pour analyser un lien dangereux sans jamais te connecter dessus.",
    },
    "dork": {
        "title": "DORK — Generateur Google / GitHub / Shodan",
        "but": "Generer des requetes de recherche avancees pretes a copier-coller sur Google, GitHub et Shodan.",
        "entree": "Un domaine (example.com) et/ou un mot-cle (ex: password, admin).",
        "mode": "100% Hors-ligne",
        "prerequis": "Aucun",
        "api_key": "Aucune",
        "examples": [
            "vortexosint dork --domain example.com",
            "vortexosint dork --domain example.com --keyword password --engine github",
        ],
        "tip": "Copie ensuite les requetes generees directement dans ton navigateur.",
    },
    "breach": {
        "title": "BREACH — Fuites de donnees & mots de passe",
        "but": "Verifier si un email apparait dans des fuites (XposedOrNot/HIBP + Gravatar) ou si un mot de passe a fuite.",
        "entree": "Un email (--email) ou un mot de passe saisi de facon masquee (--password).",
        "mode": "Internet requis",
        "prerequis": "requests (inclus de base)",
        "api_key": "Aucune obligatoire (HIBP_API_KEY optionnel pour HIBP v3)",
        "examples": [
            "vortexosint breach --email user@example.com",
            "vortexosint breach --password",
        ],
        "tip": "--password utilise k-Anonymity : ton mot de passe ne quitte jamais ton PC.",
    },
    "crypto": {
        "title": "CRYPTO — Intelligence Blockchain",
        "but": "Analyser une adresse BTC/ETH/LTC/DOGE, une transaction ou une entite (exchange).",
        "entree": "Une adresse crypto, un hash de transaction ou un nom d'entite (ex: Binance).",
        "mode": "Internet requis",
        "prerequis": "requests (inclus de base)",
        "api_key": "Aucune obligatoire (ETHERSCAN_API_KEY / BLOCKCYPHER_TOKEN optionnels)",
        "examples": [
            "vortexosint crypto --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "vortexosint crypto --tx 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            "vortexosint crypto --entity Binance",
        ],
        "tip": "Ajoute --cluster pour regrouper les adresses liees.",
    },
    "metadata": {
        "title": "METADATA — Extraction EXIF, GPS, PDF & Office",
        "but": "Lire les metadonnees cachees d'images (appareil, GPS), PDF, DOCX/XLSX ou strings d'un binaire.",
        "entree": "Un chemin de fichier (--file) ou un dossier (--dir).",
        "mode": "100% Hors-ligne",
        "prerequis": "Base Python (+ pillow, exifread, PyPDF2, python-docx, openpyxl selon le type de fichier)",
        "api_key": "Aucune",
        "examples": [
            "vortexosint metadata --file photo.jpg --exif --gps",
            "vortexosint metadata --file document.pdf",
            "vortexosint metadata --dir ./preuves --recursive",
            "vortexosint metadata --file sample.bin --strings",
        ],
        "tip": "Installe `pip install -e \".[full]\"` pour supporter tous les formats (JPG, PDF, DOCX, XLSX).",
    },
    "decode": {
        "title": "DECODE — Mini CyberChef en ligne de commande",
        "but": "Encoder/decoder Base64/Hex/URL/ROT13, lire un JWT, identifier un hash, convertir un timestamp ou calculer un CIDR.",
        "entree": "Une chaine de texte, un token JWT, un hash, un timestamp Unix ou un CIDR (192.168.1.0/24).",
        "mode": "100% Hors-ligne",
        "prerequis": "Aucun",
        "api_key": "Aucune",
        "examples": [
            "vortexosint decode --base64 \"Vm9ydGV4\"",
            "vortexosint decode --base64 \"Vortex\" --encode",
            "vortexosint decode --jwt \"eyJ...\"",
            "vortexosint decode --hash-id d41d8cd98f00b204e9800998ecf8427e",
            "vortexosint decode --timestamp 1700000000",
            "vortexosint decode --cidr 192.168.1.0/24",
        ],
        "tip": "Fonctionne instantanement sans internet ni dependance externe.",
    },
    "password": {
        "title": "PASSWORD — Generation, audit & hash",
        "but": "Generer des mots de passe cryptographiques (CSPRNG), des passphrases, auditer la force ou hasher avec sel.",
        "entree": "Aucune pour generer ; saisie masquee pour --check et --hash.",
        "mode": "100% Hors-ligne",
        "prerequis": "Aucun",
        "api_key": "Aucune",
        "examples": [
            "vortexosint password --length 20 --count 5",
            "vortexosint password --passphrase --words 6",
            "vortexosint password --check",
            "vortexosint password --hash --algo sha256",
        ],
        "tip": "La saisie masquee evite que ton mot de passe reste dans l'historique du terminal.",
    },
    "report": {
        "title": "REPORT — Generateur de rapports HTML / Markdown",
        "but": "Fusionner un ou plusieurs fichiers JSON produits avec -o en un rapport HTML ou Markdown propre.",
        "entree": "Un ou plusieurs fichiers JSON separes par des virgules (ex: osint.json,web.json).",
        "mode": "100% Hors-ligne",
        "prerequis": "Aucun",
        "api_key": "Aucune",
        "examples": [
            "vortexosint osint -d example.com -o osint.json",
            "vortexosint web -u example.com -o web.json",
            "vortexosint report --input osint.json,web.json --report-out rapport.html",
        ],
        "tip": "Extension .html = rapport visuel navigateur ; .md = rapport Markdown.",
    },
}


def show_setup_check() -> int:
    """Check Python version, installed core/optional packages, and .env API keys."""
    ui.show_module_header("PREREQUIS & DIAGNOSTIC", "Verification de ton environnement VortexOSINT")

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 8):
        ui.success(f"Python {py_ver} (OK — minimum requis : 3.8+)")
    else:
        ui.error(f"Python {py_ver} (trop ancien — installe Python 3.8 ou plus recent)")

    print()
    ui.headline("1. Dependances principales (obligatoires) :")
    missing_core: List[str] = []
    for mod, pkg, desc in CORE_DEPS:
        ok = importlib.util.find_spec(mod) is not None
        if ok:
            ui.success(f"{pkg:<16} INSTALLE   — {desc}")
        else:
            ui.error(f"{pkg:<16} MANQUANT   — {desc}")
            missing_core.append(pkg)

    print()
    ui.headline("2. Dependances optionnelles (pour PDF/Office/EXIF/Cartes) :")
    missing_opt: List[str] = []
    for mod, pkg, desc in OPTIONAL_DEPS:
        ok = importlib.util.find_spec(mod) is not None
        if ok:
            ui.success(f"{pkg:<16} INSTALLE   — {desc}")
        else:
            ui.warning(f"{pkg:<16} non inst.  — {desc}")
            missing_opt.append(pkg)

    print()
    ui.headline("3. Fichier .env & cles API (100% optionnelles) :")
    if os.path.isfile(".env"):
        ui.success("Fichier .env detecte dans le dossier courant.")
    else:
        ui.info("Aucun fichier .env (pas obligatoire — 95% des outils marchent sans cle !)")
    for env_key, desc in OPTIONAL_ENV_KEYS:
        if os.getenv(env_key):
            ui.success(f"{env_key:<18} CONFIGUREE — {desc}")
        else:
            print(f"  [-] {env_key:<18} absente    — {desc}")

    print()
    if missing_core:
        ui.warning(f"Pour installer les manquants : pip install {' '.join(missing_core)}")
    elif missing_opt:
        ui.info("Tout le coeur est pret ! Pour tout activer (PDF/Office/GPS/Cartes) : pip install -e \".[full]\"")
    else:
        ui.success("Environnement 100% complet : tous les modules et options sont prets !")
    return 0


def show_tutorial(topic: Optional[str] = None) -> int:
    """Display either the general overview tutorial, setup check, or a specific module's tutorial."""
    key = (topic or "").strip().lower()
    if key in ("setup", "check", "prerequis", "install", "env"):
        return show_setup_check()

    if key and key not in ("all", "list", "menu"):
        if key not in TUTORIALS:
            ui.error(f"Module inconnu : '{key}'. Essaie : setup, all, ou {', '.join(TUTORIALS.keys())}")
            return 1
        _print_module_tuto(key, TUTORIALS[key])
        return 0

    ui.headline("=== TUTORIEL VORTEXOSINT — CE QU'IL FAUT & MODE D'EMPLOI ===")
    print()
    ui.info("Ce qu'il te faut pour l'utiliser :")
    print("  - Python 3.8+ (verifie ton PC avec : `vortexosint tuto setup`)")
    print("  - Installation complete : `pip install -e \".[full]\"`")
    print("  - Internet : requis pour OSINT/Web/DNS/SSL/Breach ; HORS-LIGNE pour Decode/Password/Dork/Metadata/Report")
    print("  - Cles API (.env) : AUCUNE obligatoire ! (Optionnel : GITHUB_TOKEN, HIBP_API_KEY, IPINFO_TOKEN)")
    print()
    ui.info("2 facons de lancer un outil :")
    print("  1) Menu interactif : lance `vortexosint` (ou `python -m vortexosint`)")
    print("     -> Tape un numero (01..79), [N]/[B] ou [P1]/[P2] pour changer de page, [T] Tuto, [E] Quitter")
    print("  2) Ligne de commande : `vortexosint <module> [options]`")
    print("     -> Sauvegarder : `-o fichier.json` (ou `--format txt|csv`) | Aide : `vortexosint <module> --help`")
    print()

    if key == "all":
        for mod_key, data in TUTORIALS.items():
            _print_module_tuto(mod_key, data)
        return 0

    ui.headline("Les 20 modules (tape `tuto <module>` pour voir ce qu'il faut + exemples) :")
    for mod_key, data in TUTORIALS.items():
        print(f"  - {mod_key:<10} [{data['mode']:<16}] : {data['but']}")
    print()
    ui.success("Commandes utiles : `vortexosint tuto setup` (verifie ton PC) | `vortexosint tuto ssl` | `vortexosint tuto all`")
    ui.info("Tutoriel complet de A a Z disponible dans TUTORIAL.md a la racine du projet.")
    return 0


def _print_module_tuto(mod_key: str, data: Dict[str, object]) -> None:
    ui.show_module_header(f"TUTO : {mod_key}", str(data["title"]))
    print(f"  A quoi ca sert : {data['but']}")
    print(f"  Entree requise : {data['entree']}")
    print(f"  Reseau / Mode  : {data['mode']}")
    print(f"  Prerequis      : {data['prerequis']}")
    print(f"  Cle API        : {data['api_key']}")
    print("  Exemples :")
    examples: List[str] = list(data["examples"])  # type: ignore[arg-type]
    for ex in examples:
        print(f"    $ {ex}")
    print(f"  Astuce         : {data['tip']}")
    print()
