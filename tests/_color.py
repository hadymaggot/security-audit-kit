"""Warna ANSI untuk keluaran konsol — lintas Windows/macOS/Linux, aman untuk CI dan pipe.

Warna hanya dipakai saat dicetak ke layar; nilai yang disimpan ke JSON/laporan tidak pernah
berisi kode warna. Hanya 8 warna dasar ANSI (paling kompatibel: Windows Terminal, PowerShell 7,
Terminal macOS, iTerm2, GNOME Terminal, tmux, VS Code).

Aturan aktif/mati (urutan prioritas):
  1. SAK_COLOR=never|0|false|off  -> mati;   SAK_COLOR=always|1|true|on -> menyala (juga ke pipe)
     (`audit.py --color always|never|auto` / `--no-color` mengisi variabel ini untuk semua runner)
  2. NO_COLOR (apa pun yang tidak kosong, https://no-color.org) -> mati
  3. FORCE_COLOR / CLICOLOR_FORCE (selain kosong/"0") -> menyala
  4. TERM=dumb -> mati
  5. Otomatis: menyala hanya bila keluaran adalah terminal interaktif (bukan berkas/pipe/CI).
     Di Windows, mode Virtual Terminal konsol diaktifkan lebih dulu (konsol lama membutuhkannya);
     bila gagal, warna dimatikan alih-alih mencetak kode mentah.
"""
from __future__ import annotations

import os
import sys

RESET = "\033[0m"
CODES = {
    "good": "32",        # hijau
    "bad": "31",         # merah
    "badbold": "1;31",   # merah tebal
    "warn": "33",        # kuning
    "info": "36",        # sian
    "dim": "2",          # redup
    "bold": "1",
}

_OFF = {"never", "0", "false", "off", "no"}
_ON = {"always", "1", "true", "on", "yes"}
_vt_ok = None            # cache hasil aktivasi VT Windows


def _enable_windows_vt() -> bool:
    """Aktifkan ENABLE_VIRTUAL_TERMINAL_PROCESSING pada konsol Windows (no-op di OS lain)."""
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
    except Exception:  # noqa: BLE001 — tanpa ctypes/konsol: matikan warna
        _vt_ok = False
    if not _vt_ok and (os.environ.get("WT_SESSION") or os.environ.get("ConEmuANSI") == "ON"
                       or os.environ.get("ANSICON")):
        _vt_ok = True        # Windows Terminal / ConEmu / ANSICON memahami ANSI tanpa mode konsol
    return _vt_ok


def enabled(stream=None) -> bool:
    """Apakah warna dipakai untuk `stream` (default stdout) menurut aturan di docstring modul."""
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
    """Bungkus `text` dengan warna `kind` bila warna aktif; kalau tidak, kembalikan apa adanya."""
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
    """Warnai teks status menurut kata pertamanya: ok/PASS -> kata itu hijau; XX/MISS/FAIL/LEAK ->
    seluruh teks merah (sertakan alasannya); skip -> redup. Teks lain tidak diubah."""
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
    """Warnai label bertanda kurung: PASS hijau, FAIL/CRITICAL merah tebal, HIGH merah, MEDIUM
    kuning, LOW sian, INFO redup."""
    return paint(label, _TAGS.get(str(label).strip().upper(), ""))


def severity(name, text=None):
    """Warnai `text` (default: nama severity) sesuai tingkat: critical/high merah, medium kuning,
    low sian, info redup."""
    key = str(name).strip().upper()
    kind = {"CRITICAL": "badbold", "HIGH": "bad", "MEDIUM": "warn", "LOW": "info", "INFO": "dim"}.get(key, "")
    return paint(name if text is None else text, kind)
