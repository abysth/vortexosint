# 📘 Vrai Tutoriel Complet — VortexOSINT (De A à Z)

Ce guide t'explique **tout ce qu'il faut** pour installer, configurer et utiliser **VortexOSINT** correctement, même si tu débutes.

> ⚠️ **Cadre légal** : n'utilise les outils de scan (`network`, `web`, `osint`, etc.) **que** sur tes propres machines/domaines ou avec une autorisation explicite.

---

## 1. Ce qu'il faut avant de commencer (Prérequis)

### Matériel / Logiciels minimum
- **Système** : Windows 10/11, Linux ou macOS.
- **Python 3.8 ou plus récent** (vérifie avec `python --version`).
  - Sous Windows, lors de l'installation de Python (python.org), coche bien **"Add Python to PATH"**.
- **pip** (installé automatiquement avec Python).
- **Connexion Internet** : nécessaire pour les recherches en ligne (OSINT, DNS, SSL, Web, Breach…), **mais pas besoin d'internet** pour `decode`, `password`, `dork`, `metadata`, `report`, `ioc --extract/--defang`, `url --phishing`, `mac --offline`.
- **Droits administrateur** : **NON requis** pour 99% des outils (uniquement si tu fais un scan `network --scan-type syn` ; utilise `--scan-type connect` sans droits admin).

### Vérification automatique de ton PC
Une fois installé, lance simplement :
```bash
vortexosint tuto setup
# ou :
python -m vortexosint tuto setup
```
Cette commande vérifie automatiquement ta version de Python, les bibliothèques installées/manquantes et tes clés `.env`.

---

## 2. Installation pas à pas

### Option A — Installation standard (rapide, suffit pour la majorité des outils)
Ouvre un terminal (PowerShell sur Windows, Terminal sur Linux/Mac) dans le dossier du projet :
```bash
cd vortexosint
pip install -e .
```

### Option B — Installation complète (recommandée : active EXIF, GPS, PDF, Word, Excel, cartes HTML)
```bash
cd vortexosint
pip install -e ".[full]"
```

### Ce que chaque dépendance débloque
| Paquet | Type | Sert à quoi ? |
|--------|------|---------------|
| `requests`, `rich`, `colorama`, `python-dotenv`, `dnspython`, `python-whois` | **Obligatoire** | Base du CLI, affichage couleur, requêtes web/API, DNS, WHOIS |
| `pillow`, `exifread` | Optionnel | Lire EXIF et coordonnées GPS dans les photos (`metadata`) |
| `PyPDF2`, `python-docx`, `openpyxl` | Optionnel | Lire métadonnées cachées dans PDF, Word `.docx`, Excel `.xlsx` (`metadata`) |
| `folium` | Optionnel | Générer une carte interactive HTML (`geosint --map`) |

---

## 3. Clés API & fichier `.env` — Est-ce obligatoire ?

**NON !** Presque tous les outils fonctionnent **gratuitement et sans aucune clé API**.

Si tu veux lever certaines limites (quotas plus élevés ou sources en plus), crée un fichier nommé `.env` à la racine du dossier `vortexosint/` et colle uniquement les lignes qui t'intéressent :

```env
# GitHub (gratuit) : passe de 60 à 5000 requêtes/heure pour le module github
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

# HaveIBeenPwned (payant) : complète XposedOrNot (qui est gratuit) dans le module breach
HIBP_API_KEY=xxxxxxxxxxxxxxxxxxxx

# Géolocalisation IP (gratuit jusqu'à 50k req/mois sur ipinfo.io)
IPINFO_TOKEN=xxxxxxxxxxxxxxxxxxxx

# Blockchain (gratuit sur etherscan.io / blockcypher.com)
ETHERSCAN_API_KEY=xxxxxxxxxxxxxxxxxxxx
BLOCKCYPHER_TOKEN=xxxxxxxxxxxxxxxxxxxx
```

VortexOSINT charge ce fichier `.env` automatiquement au démarrage.

---

## 4. Comment lancer et naviguer

### A. Mode Menu Interactif (recommandé pour débuter)
```bash
vortexosint
# Si la commande "vortexosint" n'est pas trouvée :
python -m vortexosint
```

Le menu tient sur **2 pages** :
- **Page 1/2 (`RECON, OSINT & NETWORK`)** : outils `[01]` à `[42]`
- **Page 2/2 (`THREAT, CRYPTO, FORENSICS & UTILS`)** : outils `[43]` à `[79]`

**Ce que tu peux taper dans le menu :**
- Un **numéro** (`01`, `36`, `72`…) → lance l'outil (même s'il est sur l'autre page) et te pose les questions étape par étape.
- `N` → aller à la page 2.
- `B` → revenir à la page 1.
- `P1` ou `P2` → sauter directement sur la page 1 ou 2.
- `T` ou `tuto ssl` ou `tuto setup` → afficher le tutoriel intégré.
- `M` → réafficher le menu.
- `E` (ou `0`) → quitter.

### B. Mode Ligne de Commande Directe (plus rapide)
```bash
vortexosint <module> [options]
```
Options utiles sur **tous** les modules :
- `-o resultat.json` : enregistrer le résultat dans un fichier.
- `--format json|txt|csv` : choisir le format du fichier de sortie.
- `--no-banner` : cacher la grande bannière ASCII.
- `--no-color` : désactiver les couleurs.
- `<module> --help` : afficher toutes les options du module.

---

## 5. Tableau récapitulatif : ce qu'il faut pour chaque outil

| # | Module | Mode | Ce qu'il faut donner en entrée | Clé API ? |
|---|--------|------|-------------------------------|-----------|
| 1 | `osint` | Internet | Domaine, email, téléphone, pseudo ou IP | Non |
| 2 | `geosint` | Internet | IP, coords `"lat,lon"`, adresse, BSSID WiFi ou cellule | Non |
| 3 | `social` | Internet | Pseudo, email ou téléphone | Non |
| 4 | `github` | Internet | Pseudo GitHub | Optionnelle (`GITHUB_TOKEN`) |
| 5 | `network` | Réseau | IP/hôte/CIDR ou ASN (`AS15169`) | Non |
| 6 | `web` | Internet | URL ou domaine | Non |
| 7 | `tech` | Internet | URL ou domaine | Non |
| 8 | `ssl` | Internet | Nom de domaine (ex: `example.com`) | Non |
| 9 | `dns` | Internet | Domaine ou IP (pour `--reverse`) | Non |
| 10 | `emailsec` | Internet | Nom de domaine | Non |
| 11 | `mac` | Hybride | Adresse MAC (`AA:BB:CC:DD:EE:FF`) | Non |
| 12 | `ioc` | Hybride | Fichier log/texte, URL ou hash | Non |
| 13 | `url` | Hybride | Une URL (raccourcie ou suspecte) | Non |
| 14 | `dork` | **Hors-ligne** | Domaine et/ou mot-clé | Non |
| 15 | `breach` | Internet | Email ou mot de passe (saisie masquée) | Optionnelle (`HIBP_API_KEY`) |
| 16 | `crypto` | Internet | Adresse crypto, hash de TX ou nom d'exchange | Optionnelle |
| 17 | `metadata` | **Hors-ligne** | Fichier local (JPG, PDF, DOCX, XLSX, bin…) ou dossier | Non |
| 18 | `decode` | **Hors-ligne** | Texte Base64/Hex/URL, JWT, hash, timestamp ou CIDR | Non |
| 19 | `password` | **Hors-ligne** | Aucune (ou saisie masquée pour audit/hash) | Non |
| 20 | `report` | **Hors-ligne** | Un ou plusieurs fichiers `.json` exportés avec `-o` | Non |

---

## 6. Fiches pratiques des 20 outils (exemples prêts à lancer)

### Page 1 — Recon, OSINT & Network
```bash
# OSINT : domaine + archives Wayback Machine
vortexosint osint --domain example.com --wayback

# GEOSINT : localiser une IP ou générer une carte depuis une adresse
vortexosint geosint --ip 8.8.8.8
vortexosint geosint --address "Tour Eiffel, Paris" --map

# SOCIAL : vérifier un pseudo sur les réseaux
vortexosint social --username johndoe --platforms github,reddit,twitter

# GITHUB : profil, repos, clés SSH et emails des commits
vortexosint github --username octocat

# NETWORK : ton IP publique, ping, scan de ports, ASN
vortexosint network --my-ip
vortexosint network --ping 8.8.8.8
vortexosint network --target scanme.nmap.org --ports 22,80,443 --scan-type connect
vortexosint network --asn AS15169

# WEB : note de sécurité A-F + robots.txt / security.txt / redirections
vortexosint web --url https://example.com

# TECH : savoir quel serveur / CDN / CMS / framework tourne sur le site
vortexosint tech --url https://example.com

# SSL : certificat TLS + sous-domaines via crt.sh
vortexosint ssl --host example.com --ct

# DNS : tous les enregistrements + sous-domaines passifs + reverse DNS
vortexosint dns --domain example.com --subdomains
vortexosint dns --reverse 8.8.8.8

# EMAILSEC : audit anti-spoofing SPF / DMARC / DKIM + propagation DNS
vortexosint emailsec --domain example.com --propagation

# MAC : trouver le fabricant et détecter une MAC aléatoire/spoofée
vortexosint mac --mac B8:27:EB:11:22:33
```

### Page 2 — Threat, Crypto, Forensics & Utils
```bash
# IOC : extraire les indicateurs d'un fichier log et sécuriser un lien (defang)
vortexosint ioc --extract alert.log
vortexosint ioc --defang https://evil.com/login

# URL : dérouler un lien raccourci ou analyser le phishing hors-ligne
vortexosint url --url https://bit.ly/exemple
vortexosint url --url "http://192.168.1.1/login-verify" --phishing

# DORK : générer des requêtes Google / GitHub / Shodan
vortexosint dork --domain example.com --keyword secret

# BREACH : vérifier un email dans les fuites ou un mot de passe (k-Anonymity)
vortexosint breach --email user@example.com
vortexosint breach --password

# CRYPTO : analyser une adresse ou une transaction blockchain
vortexosint crypto --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# METADATA : lire EXIF/GPS d'une photo ou métadonnées d'un PDF
vortexosint metadata --file photo.jpg --exif --gps
vortexosint metadata --file document.pdf

# DECODE : Base64, JWT, Hash-ID, Timestamp, CIDR (100% hors-ligne)
vortexosint decode --base64 "Vm9ydGV4"
vortexosint decode --jwt "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"
vortexosint decode --hash-id d41d8cd98f00b204e9800998ecf8427e
vortexosint decode --cidr 192.168.1.0/24

# PASSWORD : générer des mots de passe forts, passphrases ou auditer
vortexosint password --length 20 --count 5
vortexosint password --passphrase --words 6
vortexosint password --check

# REPORT : fusionner des résultats JSON en rapport HTML ou Markdown
vortexosint report --input dns.json,web.json,ssl.json --report-out rapport.html
```

---

## 7. Exemple de mission complète (de A à Z)

Tu veux auditer un domaine (`example.com`) et sortir un rapport HTML propre :
```bash
vortexosint dns --domain example.com --subdomains -o 1_dns.json
vortexosint web --url https://example.com -o 2_web.json
vortexosint tech --url https://example.com -o 3_tech.json
vortexosint ssl --host example.com --ct -o 4_ssl.json
vortexosint emailsec --domain example.com -o 5_emailsec.json
vortexosint report --input 1_dns.json,2_web.json,3_tech.json,4_ssl.json,5_emailsec.json --report-out audit_example.html --title "Audit example.com"
```
Ouvre ensuite `audit_example.html` dans ton navigateur !

---

## 8. Dépannage rapide (Problèmes fréquents)

- **`vortexosint` n'est pas reconnu dans le terminal** :
  - Utilise `python -m vortexosint` à la place, ou réinstalle avec `pip install -e .` en vérifiant que le dossier `Scripts` de Python est dans le `PATH`.
- **`ModuleNotFoundError: No module named ...`** :
  - Lance `vortexosint tuto setup` pour voir quel paquet manque, puis `pip install -e ".[full]"`.
- **Erreur de permission sur `network --scan-type syn`** :
  - Le scan SYN demande les droits admin/root. Ajoute `--scan-type connect` pour scanner sans droits admin.
- **GitHub répond `403 rate limit exceeded`** :
  - Crée un token gratuit sur GitHub (Settings → Developer settings → Personal access tokens) et ajoute `GITHUB_TOKEN=...` dans `.env`.
- **Un site met du temps ou timeout** :
  - Augmente le délai avec `--timeout 30` sur les modules qui le supportent (`osint`, `web`, `ssl`, `url`, `tech`).
