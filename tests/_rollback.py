"""Cross-module rollback journal: lets destructive tests leave the target as they found it.

Principle: every action that CHANGES target state is written to the journal IMMEDIATELY after it
runs (crash-safe). At the end of a scan, after the report is built, `replay()` reverses each
entry not yet restored, so the target returns to its original state.

This module deliberately has no network: it only manages the journal file and calls the
caller-supplied `do_restore(entry)` callback to send the restore request, which keeps the
logic easy to unit test.

Journal: reports/rollback_journal.json  (list of entries)
Restore log: reports/rollback.json
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
    """Record one destructive action and how to reverse it.

    Runners call this IMMEDIATELY after writing to the target (before verification) so even a
    crash leaves a journal that can be replayed.

    Minimal entry: {label, module, action}. 'action' is the restore instruction understood by
    do_restore (e.g. {method, path, json} or {method: DELETE, path}).
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
    """Restore every entry not yet 'done'.

    `do_restore(entry)` -> (ok, note) sends the restore request. Successful entries are marked
    done; a summary is written to reports/rollback.json. Idempotent: done entries are skipped.
    """
    journal = load(reports_dir)
    results = []
    for e in journal:
        if e.get("done"):
            continue
        try:
            ok, note = do_restore(e)
        except Exception as exc:  # noqa: BLE001
            ok, note = False, f"error: {exc}"
        e["done"] = bool(ok)
        results.append({"label": e.get("label", "?"), "ok": bool(ok), "note": note})
    _write(reports_dir, journal)
    failed = sum(1 for r in results if not r["ok"])
    _p(reports_dir, LOG).write_text(
        json.dumps({"module": "rollback", "restored": len(results) - failed,
                    "failed": failed, "results": results}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    return results


def clear(reports_dir):
    """Delete the journal (e.g. after everything is restored and confirmed)."""
    p = _p(reports_dir, JOURNAL)
    if p.exists():
        p.unlink()
