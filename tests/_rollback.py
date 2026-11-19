"""Jurnal rollback lintas-modul — nilai plus kit ini: uji destruktif yang
'rasa non-destruktif'.

Prinsip: setiap aksi yang MENGUBAH state target dicatat ke jurnal SEGERA setelah
dieksekusi (crash-safe). Di akhir scan — setelah laporan dibuat — `replay()` membalikkan
tiap entri yang belum dipulihkan, sehingga target kembali ke keadaan semula.

Modul ini sengaja tanpa jaringan: ia hanya mengelola berkas jurnal dan memanggil
callback `do_restore(entry)` yang disediakan pemanggil untuk mengirim request pemulihan.
Dengan begitu logikanya mudah diuji unit.

Jurnal: reports/rollback_journal.json  (daftar entri)
Log pemulihan: reports/rollback.json
"""
from __future__ import annotations

import json
from pathlib import Path

JOURNAL = "rollback_journal.json"
LOG = "rollback.json"


def _p(reports_dir, name):
    return Path(reports_dir) / name


def load(reports_dir):
    p = _p(reports_dir, JOURNAL)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:  # noqa: BLE001
        return []


def _write(reports_dir, data):
    p = _p(reports_dir, JOURNAL)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def record(reports_dir, entry):
    """Catat satu aksi destruktif + cara membalikkannya. Dipanggil runner SEGERA
    setelah menulis ke target (sebelum verifikasi), supaya crash pun meninggalkan
    jurnal yang bisa di-replay.

    entry minimal: {label, module, action}. 'action' adalah instruksi pemulihan yang
    dimengerti do_restore (mis. {method, path, json} atau {method: DELETE, path}).
    """
    data = load(reports_dir)
    e = dict(entry)
    e.setdefault("done", False)
    data.append(e)
    _write(reports_dir, data)
    return e


def pending(reports_dir):
    return [e for e in load(reports_dir) if not e.get("done")]


def replay(reports_dir, do_restore):
    """Pulihkan tiap entri yang belum 'done'. `do_restore(entry)` -> (ok, catatan)
    mengirim request pemulihan. Entri yang berhasil ditandai done; ringkasan ditulis
    ke reports/rollback.json. Idempoten: entri done dilewati.
    """
    journal = load(reports_dir)
    results = []
    for e in journal:
        if e.get("done"):
            continue
        try:
            ok, note = do_restore(e)
        except Exception as exc:  # noqa: BLE001
            ok, note = False, f"galat: {exc}"
        e["done"] = bool(ok)
        results.append({"label": e.get("label", "?"), "ok": bool(ok), "note": note})
    _write(reports_dir, journal)
    gagal = sum(1 for r in results if not r["ok"])
    _p(reports_dir, LOG).write_text(
        json.dumps({"module": "rollback", "dipulihkan": len(results) - gagal,
                    "gagal": gagal, "results": results}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    return results


def clear(reports_dir):
    """Hapus jurnal (mis. setelah semua dipulihkan & dikonfirmasi)."""
    p = _p(reports_dir, JOURNAL)
    if p.exists():
        p.unlink()
