"""ANSI colors for console output: cross-platform (Windows/macOS/Linux), safe for CI and pipes.

Colors are applied only when printing to the screen; values saved to JSON/reports never contain
color codes. Only the 8 basic ANSI colors are used (most compatible: Windows Terminal,
PowerShell 7, macOS Terminal, iTerm2, GNOME Terminal, tmux, VS Code).

On/off rules (priority order):
  1. SAK_COLOR=never|0|false|off  -> off;   SAK_COLOR=always|1|true|on -> on (even to a pipe)
     (`audit.py --color always|never|auto` / `--no-color` sets this variable for every runner)
  2. NO_COLOR (any non-empty value, https://no-color.org) -> off
  3. FORCE_COLOR / CLICOLOR_FORCE (anything but empty/"0") -> on
  4. TERM=dumb -> off
  5. Auto: on only when the output is an interactive terminal (not a file/pipe/CI).
     On Windows the console's Virtual Terminal mode is enabled first (legacy consoles need it);
     if that fails, color is turned off rather than printing raw escape codes.
"""
from __future__ import annotations

import os
import sys

RESET = "\033[0m"
CODES = {
    "good": "32",        # green
    "bad": "31",         # red
    "badbold": "1;31",   # bold red
    "warn": "33",        # yellow
    "info": "36",        # cyan
    "dim": "2",          # dim
    "bold": "1",
}

_OFF = {"never", "0", "false", "off", "no"}
_ON = {"always", "1", "true", "on", "yes"}
_vt_ok = None            # cached result of enabling Windows VT mode


def _enable_windows_vt() -> bool:
    """Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING on the Windows console (no-op on other OSes)."""
    global _vt_ok
    if _vt_ok is not None:
        return _vt_ok
    if os.name != "nt":
        _vt_ok = True
        return True
    try:
        import ctypes

        k32 = ctypes.windll.kernel32
        k32.GetStdHandle.restype = ctypes.c_void_p
        k32.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        k32.SetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        ok = False
        for std in (-11, -12):                       # STDOUT, STDERR
            handle = k32.GetStdHandle(std)
            mode = ctypes.c_ulong()
            if handle and k32.GetConsoleMode(handle, ctypes.byref(mode)):
                if mode.value & 0x0004 or k32.SetConsoleMode(handle, mode.value | 0x0004):
                    ok = ok or std == -11
        _vt_ok = bool(ok)
    except Exception:  # noqa: BLE001 — no ctypes/console: turn color off
        _vt_ok = False
    if not _vt_ok and (os.environ.get("WT_SESSION") or os.environ.get("ConEmuANSI") == "ON"
                       or os.environ.get("ANSICON")):
        _vt_ok = True        # Windows Terminal / ConEmu / ANSICON understand ANSI without console mode
    return _vt_ok


def enabled(stream=None) -> bool:
    """Whether color is used for `stream` (default stdout), per the rules in the module docstring."""
    mode = os.environ.get("SAK_COLOR", "").strip().lower()
    if mode in _OFF:
        return False
    if mode in _ON:
        _enable_windows_vt()
        return True
    if os.environ.get("NO_COLOR"):
        return False
    for var in ("FORCE_COLOR", "CLICOLOR_FORCE"):
        if os.environ.get(var, "") not in ("", "0"):
            _enable_windows_vt()
            return True
    if os.environ.get("TERM") == "dumb":
        return False
    stream = stream if stream is not None else sys.stdout
    try:
        if not stream.isatty():
            return False
    except Exception:  # noqa: BLE001
        return False
    return _enable_windows_vt()


def paint(text, kind: str, stream=None) -> str:
    """Wrap `text` in the `kind` color when color is on; otherwise return it unchanged."""
    text = str(text)
    if not text or kind not in CODES or not enabled(stream):
        return text
    return f"\033[{CODES[kind]}m{text}{RESET}"


def good(text):
    return paint(text, "good")


def bad(text):
    return paint(text, "bad")


def warn(text):
    return paint(text, "warn")


def info(text):
    return paint(text, "info")


def dim(text):
    return paint(text, "dim")


def bold(text):
    return paint(text, "bold")


_GOOD = {"ok", "pass", "lolos", "aman"}
_BAD = {"xx", "miss", "fail", "gagal", "leak", "error"}
_DIM = {"skip"}


def status(text):
    """Color status text by its first word: ok/PASS -> that word green; XX/MISS/FAIL/LEAK ->
    whole text red (reason included); skip -> dim. Other text is unchanged."""
    s = str(text)
    parts = s.split(None, 1)
    if not parts:
        return s
    first = parts[0].strip("[]:").lower()
    if first in _GOOD:
        head = parts[0]
        return paint(head, "good") + s[s.index(head) + len(head):]
    if first in _BAD:
        return paint(s, "bad")
    if first in _DIM:
        return paint(s, "dim")
    return s


_TAGS = {"PASS": "good", "OK": "good", "FAIL": "badbold", "CRITICAL": "badbold", "HIGH": "bad",
         "MEDIUM": "warn", "LOW": "info", "INFO": "dim"}


def tag(label):
    """Color a bracketed label: PASS green, FAIL/CRITICAL bold red, HIGH red, MEDIUM
    yellow, LOW cyan, INFO dim."""
    return paint(label, _TAGS.get(str(label).strip().upper(), ""))


def severity(name, text=None):
    """Color `text` (default: the severity name) by level: critical/high red, medium yellow,
    low cyan, info dim."""
    key = str(name).strip().upper()
    kind = {"CRITICAL": "badbold", "HIGH": "bad", "MEDIUM": "warn", "LOW": "info", "INFO": "dim"}.get(key, "")
    return paint(name if text is None else text, kind)
