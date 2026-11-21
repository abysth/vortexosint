"""
Central UI helpers for VortexOSINT.

Uses `rich` when available (tables, panels, prompts) and falls back
to plain printing with ANSI colors otherwise, so the CLI works
everywhere with or without optional dependencies.

All output goes through this module: banner, module headers,
status messages, tables and interactive prompts.
"""

import sys
import shutil

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich import box

    _HAS_RICH = True
except ImportError:  # pragma: no cover - fallback path
    _HAS_RICH = False

from vortexosint.core.colors import Colors

# Set to True by --no-color: forces plain output even if rich is present.
PLAIN_MODE = False

_console = None


def set_plain_mode(plain: bool = True):
    """Force plain (no rich / no color) output. Called for --no-color."""
    global PLAIN_MODE, _console
    PLAIN_MODE = plain
    _console = None
    if plain:
        Colors.disable()


def get_console():
    """Return a shared rich Console, or None in plain/fallback mode."""
    global _console
    if PLAIN_MODE or not _HAS_RICH:
        return None
    if _console is None:
        # Soft wrap + no highlight: we control styling explicitly.
        _console = Console(highlight=False, soft_wrap=False)
    return _console


def _box():
    """ROUNDED borders when the output encoding supports them, else ASCII.

    Prevents UnicodeEncodeError on Windows consoles piped with cp1252.
    """
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "─│┌┐└┘".encode(enc)
        return box.ROUNDED
    except (UnicodeEncodeError, LookupError, AttributeError):
        return box.ASCII


def _box_is_ascii() -> bool:
    return _box() is box.ASCII


def _out(text: str = "", style: str = ""):
    """Print styled text via rich, or plain print as fallback."""
    console = get_console()
    if console is not None:
        console.print(text, style=style, markup=False, highlight=False)
    else:
        print(text)


# ---------------------------------------------------------------------------
# Status / message helpers (single place for the [*, +, !, ~] conventions)
# ---------------------------------------------------------------------------

def info(text: str):
    _out(f"[*] {text}", style="cyan")


def success(text: str):
    _out(f"[+] {text}", style="green")


def error(text: str):
    _out(f"[!] {text}", style="red")


def warning(text: str):
    _out(f"[!] {text}", style="yellow")


def step(text: str):
    _out(f"[~] {text}", style="yellow")


def headline(text: str):
    """Bold section headline inside a module run."""
    console = get_console()
    if console is not None:
        console.print(text, style="bold cyan", markup=False, highlight=False)
    else:
        print(f"{Colors.CYAN}{Colors.BOLD}{text}{Colors.RESET}")


def divider():
    """Visual separator at the end of a module run."""
    console = get_console()
    if console is not None:
        if _box_is_ascii():
            console.rule(characters="-", style="cyan")
        else:
            console.rule(style="cyan")
    else:
        print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")


# ---------------------------------------------------------------------------
# Banner & headers
# ---------------------------------------------------------------------------

VORTEX_ART = r"""
                     @@@         
            @      @@@@@@@@@@@   
          @@     @@       @@@@@@ 
         @@    @   @@@@@@   @@   
       @@@@     @@@@@    @@  @@  
 @    @@@@  @ @@@@@  @@@  @  @@  
 @    @@@  @ @@@@@@@  @@  @  @@  
    @@@   @  @%@@@@@  @@  @  :@  
   @@@   @  @@@@@@%  @@   @@     
  @@@@  @@    @    @@@     @     
  @@@   @@@      @@@@     @@     
 @@@@    @@@@@@@@@      @@       
 @@@@                  @@        
  @@@@          @@   @@          
  @@@@@@@@@@@@@    @@    @@      
     @@@@@@@@@                   
"""

LOGO = r"""
//    ____   ____________ ____________________________________  ___
//    \   \ /   /\_____  \\______   \__    ___/\_   _____/\   \/  /
//     \   Y   /  /   |   \|       _/ |    |    |    __)_  \     / 
//      \     /  /    |    \    |   \ |    |    |        \ /     \ 
//       \___/   \_______  /____|_  / |____|   /_______  //___/\  \
//                       \/       \/                   \/       \_/
"""

TAGLINE = "Multi-tool OSINT / GEOSINT reconnaissance framework"


def show_banner(version: str):
    """Print the main VortexOSINT banner with vortex art side-by-side with VORTEX text."""
    art_lines = [line.rstrip("\r") for line in VORTEX_ART.splitlines() if line.strip()]
    logo_lines = [line.rstrip("\r") for line in LOGO.splitlines() if line.strip()]
    art_w = max(len(l) for l in art_lines)
    logo_w = max(len(l) for l in logo_lines)

    right_block = (
        [(l, "bold bright_cyan") for l in logo_lines]
        + [("", "")]
        + [(TAGLINE.center(logo_w), "bold white")]
        + [(f"v{version}  |  github.com/abysth/vortexosint".center(logo_w), "dim cyan")]
    )
    start_row = max(0, (len(art_lines) - len(right_block)) // 2)

    console = get_console()
    if console is not None:
        side_by_side = (console.width or 120) >= (art_w + logo_w + 10)
        body = Text()
        if side_by_side:
            for i, line in enumerate(art_lines):
                body.append(line.ljust(art_w), style="bold cyan")
                r_idx = i - start_row
                if 0 <= r_idx < len(right_block):
                    r_text, r_style = right_block[r_idx]
                    if r_text:
                        body.append("   " + r_text, style=r_style)
                if i < len(art_lines) - 1:
                    body.append("\n")
        else:
            for line in art_lines:
                body.append(line.center(logo_w) + "\n", style="bold cyan")
            body.append("\n")
            for idx, (r_text, r_style) in enumerate(right_block):
                suffix = "\n" if idx < len(right_block) - 1 else ""
                body.append(r_text + suffix, style=r_style)
        console.print(
            Panel(
                body,
                border_style="bright_blue",
                box=_box(),
                padding=(0, 2),
                expand=True,
            )
        )
    else:
        for i, line in enumerate(art_lines):
            r_idx = i - start_row
            extra = f"   {right_block[r_idx][0]}" if 0 <= r_idx < len(right_block) and right_block[r_idx][0] else ""
            print(Colors.cyan(line.ljust(art_w)) + extra)
        print()


def show_module_header(name: str, description: str):
    """Print a module-specific header."""
    console = get_console()
    if console is not None:
        console.print(
            Panel(
                f"[white]{description}[/white]",
                title=f"[bold bright_cyan]{name.upper()}[/]",
                border_style="bright_blue",
                box=_box(),
                padding=(0, 2),
            )
        )
    else:
        print(Colors.cyan(f"\n+{'-' * 60}+"))
        print(Colors.cyan(f"|  {name.upper():<56}|"))
        print(Colors.cyan(f"+{'-' * 60}+"))
        print(Colors.dim(f"  {description}\n"))


# ---------------------------------------------------------------------------
# Module catalog (shared by --help, menu and docs)
# ---------------------------------------------------------------------------

MODULES = {
    "osint": {
        "label": "OSINT",
        "description": "Domains, emails, phones, usernames, IPs",
        "example": "osint --domain example.com",
    },
    "geosint": {
        "label": "GEOSINT",
        "description": "IP geolocation, coords, addresses, WiFi/cell",
        "example": "geosint --ip 8.8.8.8",
    },
    "network": {
        "label": "NETWORK",
        "description": "Port scans, services, OS detection, ASN",
        "example": "network --target 192.168.1.0/24",
    },
    "crypto": {
        "label": "CRYPTO",
        "description": "Addresses, transactions, entities",
        "example": "crypto --address 1A1zP1...",
    },
    "social": {
        "label": "SOCIAL",
        "description": "Usernames across 50+ platforms",
        "example": "social --username johndoe",
    },
    "metadata": {
        "label": "METADATA",
        "description": "EXIF, GPS, PDF & Office metadata",
        "example": "metadata --file document.pdf",
    },
    "password": {
        "label": "PASSWORD",
        "description": "Secure passwords, passphrases & audits",
        "example": "password --length 20 --count 5",
    },
}

MODULE_ORDER = ["osint", "geosint", "network", "crypto", "social", "metadata", "password"]


def show_modules_table():
    """Print the module catalog as a rich table (or plain list)."""
    console = get_console()
    if console is not None:
        table = Table(
            title="Available modules",
            box=_box(),
            border_style="cyan",
            header_style="bold yellow",
            show_lines=False,
        )
        table.add_column("#", justify="right", style="dim", width=3)
        table.add_column("Module", style="bold cyan", width=10)
        table.add_column("Description", style="")
        table.add_column("Example", style="dim")
        for i, key in enumerate(MODULE_ORDER, start=1):
            m = MODULES[key]
            table.add_row(str(i), m["label"], m["description"], f"vortexosint {m['example']}")
        console.print(table)
    else:
        print("\nAvailable modules:")
        for i, key in enumerate(MODULE_ORDER, start=1):
            m = MODULES[key]
            print(f"  {i}. {m['label']:<10} {m['description']}")
            print(f"     ex: vortexosint {m['example']}")
        print()


# ---------------------------------------------------------------------------
# Interactive prompts (menu mode)
# ---------------------------------------------------------------------------

def _read_plain(prompt_text: str, default: str = "") -> str:
    """input()-based prompt used when rich is unavailable."""
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"{prompt_text}{suffix}: ").strip()
    except EOFError:
        return ""
    return value if value else default


def ask(text: str, default: str = "") -> str:
    """Ask for a free-text value. Empty input returns `default`."""
    if PLAIN_MODE or not _HAS_RICH:
        return _read_plain(text, default)
    try:
        answer = Prompt.ask(f"[cyan]{text}[/]", default=default or None, show_default=bool(default))
    except (EOFError, KeyboardInterrupt):
        raise
    return (answer or "").strip() if isinstance(answer, str) else (answer or "")


def ask_yes_no(text: str, default: bool = False) -> bool:
    """Ask a yes/no question."""
    if PLAIN_MODE or not _HAS_RICH:
        hint = "Y/n" if default else "y/N"
        try:
            value = input(f"{text} [{hint}]: ").strip().lower()
        except EOFError:
            return default
        if not value:
            return default
        return value in ("y", "yes", "o", "oui")
    try:
        return Confirm.ask(f"[cyan]{text}[/]", default=default)
    except (EOFError, KeyboardInterrupt):
        raise


def ask_choice(text: str, choices: list, default: str) -> str:
    """Ask to pick one value among `choices`."""
    if PLAIN_MODE or not _HAS_RICH:
        shown = "/".join(choices)
        try:
            value = input(f"{text} [{shown}, défaut: {default}]: ").strip().lower()
        except EOFError:
            return default
        return value if value in choices else default
    try:
        answer = Prompt.ask(
            f"[cyan]{text}[/]",
            choices=choices,
            default=default,
            show_choices=True,
            show_default=True,
        )
    except (EOFError, KeyboardInterrupt):
        raise
    return answer or default


def pause():
    """Wait for Enter (used between menu runs)."""
    try:
        input("\nAppuie sur Entrée pour continuer...")
    except EOFError:
        pass


# ---------------------------------------------------------------------------
# Retro menu (paged, numbered, Kali-style prompt)
# ---------------------------------------------------------------------------

RETRO_LINK = "https://github.com/abysth/vortexosint"


def show_retro_title():
    """Centered title block in unified cyan/blue."""
    console = get_console()
    if console is not None:
        width = console.width or 80
        console.print("VortexOSINT Multi-Tool".center(width),
                      style="bold bright_cyan", markup=False, highlight=False)
        console.print(f"[{RETRO_LINK}]".center(width),
                      style="dim cyan", markup=False, highlight=False)
    else:
        print(Colors.colorize("VortexOSINT Multi-Tool".center(70),
                              Colors.BOLD + Colors.BRIGHT_BLUE))
        print(Colors.colorize(f"[{RETRO_LINK}]".center(70), Colors.BLUE))


def _retro_entries(cells):
    """Format [(num, label)] cells for one category column."""
    return "\n".join(f"[{n}] {label}" for n, label in cells)


def show_retro_page(title, columns):
    """Render one menu page.

    columns: list of (header, [(num_str, label), ...]).
    Numbers are global across pages (01, 02, ...).
    """
    console = get_console()
    if console is not None:
        table = Table(title=title, box=_box(), border_style="magenta",
                      header_style="bold magenta", show_lines=False)
        for header, _cells in columns:
            table.add_column(header, style="red", overflow="fold")
        table.add_row(*[_retro_entries(cells) for _header, cells in columns])
        console.print(table)
        return

    # Plain ASCII fallback (cp1252-safe).
    try:
        term_width = shutil.get_terminal_size().columns
    except Exception:
        term_width = 80
    col_w = 26
    ncols = len(columns)
    if term_width < ncols * (col_w + 1):
        # Stack vertically on narrow terminals.
        for header, cells in columns:
            print(f"+{'-' * col_w}+")
            print(f"|{header.center(col_w)}|")
            print(f"+{'-' * col_w}+")
            for num, label in cells:
                print(f"  [{num}] {label}")
            print()
        return
    print("+" + "+".join(["-" * col_w] * ncols) + "+")
    print("|" + "|".join(h.center(col_w) for h, _c in columns) + "|")
    print("+" + "+".join(["-" * col_w] * ncols) + "+")
    max_rows = max(len(cells) for _h, cells in columns)
    for i in range(max_rows):
        row = []
        for _h, cells in columns:
            cell = f"[{cells[i][0]}] {cells[i][1]}" if i < len(cells) else ""
            row.append(" " + cell[:col_w - 1].ljust(col_w - 1))
        print("|" + "|".join(row) + "|")
    print("+" + "+".join(["-" * col_w] * ncols) + "+")


def show_retro_nav(has_next, has_back):
    """Navigation hints under the menu."""
    parts = []
    if has_back:
        parts.append("[B] Back")
    if has_next:
        parts.append("[N] Next")
    parts.append("[M] Menu")
    parts.append("[E] Exit")
    line = "  |- " + " | ".join(parts)
    console = get_console()
    if console is not None:
        console.print(line, style="dim bright_cyan", markup=False, highlight=False)
    else:
        print(Colors.blue(line))


def retro_input():
    """Unified cyan/blue prompt. Returns stripped input, or None on EOF."""
    prompt = (
        f"{Colors.BRIGHT_BLUE}({Colors.BOLD}{Colors.BRIGHT_CYAN}vortex"
        f"{Colors.RESET}{Colors.BRIGHT_BLUE})-[{Colors.CYAN}~/menu"
        f"{Colors.BRIGHT_BLUE}]$ {Colors.RESET}"
    )
    try:
        return input(prompt).strip()
    except EOFError:
        return None


def show_retro_single(groups):
    """Single-page menu in unified cyan/blue/white: framed panel (rich) or ASCII box (fallback)."""
    console = get_console()
    if console is None:
        width = 74
        print("+" + "-" * width + "+")
        for header, cells in groups:
            print(f"| -- {header} --".ljust(width + 1) + "|")
            for i in range(0, len(cells), 3):
                row = cells[i:i + 3]
                line = "".join(f"  [{num}] {label[:17]}".ljust(24)
                               for num, label in row)
                print("|" + line.ljust(width) + "|")
        print("+" + "-" * width + "+")
        return
    body = Text()
    first = True
    for header, cells in groups:
        if not first:
            body.append("\n")
        first = False
        body.append(f"-- {header} --\n", style="bold bright_cyan")
        for i in range(0, len(cells), 3):
            for num, label in cells[i:i + 3]:
                body.append("  [", style="dim cyan")
                body.append(num, style="bold cyan")
                body.append("] ", style="dim cyan")
                body.append(f"{label[:17]}".ljust(20), style="white")
            body.append("\n")
    console.print(Panel(body, title="[bold bright_cyan]TOOLS[/]", border_style="bright_blue",
                        box=_box(), padding=(0, 2)))
