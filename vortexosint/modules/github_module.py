"""
GitHub Module - Developer OSINT via Official Public GitHub API
"""

import argparse
import os
from typing import Any, Dict, List

from vortexosint.core.banner import print_module_banner
from vortexosint.core.colors import Colors
from vortexosint.core.output import output_results as _output_results


def _gh_headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "VortexOSINT/1.0",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def investigate_github_user(username: str) -> Dict[str, Any]:
    """Gather public GitHub profile, orgs, repos, SSH keys & commit emails."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}

    u = (username or "").strip().lstrip("@")
    headers = _gh_headers()
    base = "https://api.github.com"

    print(f"  {Colors.YELLOW}[~] Fetching GitHub profile...{Colors.RESET}")
    try:
        prof_resp = requests.get(f"{base}/users/{u}", headers=headers, timeout=12)
        if prof_resp.status_code == 404:
            return {"username": u, "found": False, "error": "User not found"}
        if prof_resp.status_code != 200:
            return {"username": u, "error": f"GitHub API HTTP {prof_resp.status_code}"}
        p = prof_resp.json()
    except Exception as e:
        return {"username": u, "error": str(e)}

    profile = {
        "login": p.get("login"),
        "name": p.get("name"),
        "bio": p.get("bio"),
        "company": p.get("company"),
        "location": p.get("location"),
        "blog": p.get("blog"),
        "email": p.get("email"),
        "twitter": p.get("twitter_username"),
        "public_repos": p.get("public_repos"),
        "followers": p.get("followers"),
        "following": p.get("following"),
        "created_at": p.get("created_at"),
        "url": p.get("html_url"),
    }

    # Organizations
    orgs: List[str] = []
    try:
        r = requests.get(f"{base}/users/{u}/orgs", headers=headers, timeout=10)
        if r.status_code == 200:
            orgs = [o.get("login", "") for o in r.json() if o.get("login")]
    except Exception:
        pass

    # Top repos & languages
    repos: List[Dict[str, Any]] = []
    languages: Dict[str, int] = {}
    try:
        r = requests.get(
            f"{base}/users/{u}/repos",
            params={"sort": "updated", "per_page": 10},
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            for repo in r.json():
                lang = repo.get("language")
                if lang:
                    languages[lang] = languages.get(lang, 0) + 1
                repos.append({
                    "name": repo.get("name"),
                    "stars": repo.get("stargazers_count", 0),
                    "language": lang or "",
                    "url": repo.get("html_url"),
                })
    except Exception:
        pass

    # Public SSH keys
    ssh_keys: List[str] = []
    try:
        r = requests.get(f"https://github.com/{u}.keys", timeout=8)
        if r.status_code == 200 and r.text.strip():
            ssh_keys = [line.strip()[:60] + "..." for line in r.text.splitlines() if line.strip()]
    except Exception:
        pass

    # Commit emails from public PushEvents
    commit_emails = set()
    try:
        r = requests.get(f"{base}/users/{u}/events/public", params={"per_page": 30},
                         headers=headers, timeout=10)
        if r.status_code == 200:
            for ev in r.json():
                if ev.get("type") == "PushEvent":
                    for c in ev.get("payload", {}).get("commits", []):
                        email = (c.get("author") or {}).get("email", "")
                        if email and "noreply.github.com" not in email.lower():
                            commit_emails.add(email)
    except Exception:
        pass

    return {
        "found": True,
        "profile": profile,
        "organizations": orgs,
        "languages": languages,
        "recent_repos": repos,
        "ssh_keys_count": len(ssh_keys),
        "ssh_keys_preview": ssh_keys[:5],
        "public_commit_emails": sorted(commit_emails),
    }


def run(args: argparse.Namespace) -> int:
    """Run the GitHub OSINT module."""
    print_module_banner("GITHUB", "Developer OSINT (Profiles, Repos, Keys & Commit Emails)")
    username = getattr(args, "username", None)
    if not username:
        print(f"{Colors.RED}[!] No username specified. Use --username <github_user>{Colors.RESET}")
        return 1

    print(f"\n{Colors.CYAN}[*] Investigating GitHub user: {Colors.BOLD}{username}{Colors.RESET}")
    results = {username: {"target": username, "type": "github", "findings": investigate_github_user(username)}}
    _output_results(results, args, mode="target")
    return 0
