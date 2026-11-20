"""Snapshot data (rollback level data) untuk scan aktif/destruktif — lintas-modul.

Jurnal rollback (`_rollback.py`) hanya dapat membalik tindakan yang DIKENAL satu per satu (mis. PATCH
nilai asli). Scan aktif seperti ZAP full menulis ke banyak endpoint secara acak, sehingga satu-satunya
rollback yang realistis adalah memulihkan DATA: ambil snapshot sebelum scan, pulihkan sesudahnya.

Konfigurasi (blok `snapshot:` pada config/targets.yml):

  snapshot:
    keep: false                       # hapus berkas snapshot setelah berhasil dipulihkan
    timeout_seconds: 1800
    steps:                            # setiap langkah = satu pasang backup/restore (argv, tanpa shell)
      - name: "postgres auth"
        backup:  { cmd: ["docker","exec","pg","pg_dump","-U","u","-Fc","auth"], stdout_to: "{dir}/auth.dump" }
        restore: { cmd: ["docker","exec","-i","pg","pg_restore","-U","u","-d","auth","--clean",
                         "--if-exists","--no-owner","--single-transaction"], stdin_from: "{dir}/auth.dump" }

  Atau preset ringkas untuk PostgreSQL di Docker:
    snapshot: { preset: postgres-docker, container: app-postgres-1, user: app-user,
                databases: [auth, orders] }

Placeholder {dir} = direktori snapshot. Perintah dijalankan tanpa shell (argv). Backup yang gagal atau
berkas kosong MEMBATALKAN scan (tidak ada scan tanpa jaring pengaman). Entri jurnal rollback dicatat
sebelum scan sehingga `python audit.py rollback` dapat memulihkan bila proses mati di tengah jalan.

Catatan cakupan: hanya data yang dicakup langkah snapshot yang dipulihkan (mis. PostgreSQL). Penyimpanan
objek (MinIO/S3), antrean (RabbitMQ), dan cache (Redis) tidak ikut kecuali Anda menambah langkahnya.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _rollback  # noqa: E402
import _color as C  # noqa: E402  (warna ANSI konsol lintas-modul di tests/)


class SnapshotError(RuntimeError):
    pass


def default_runner(cmd, stdin_path=None, stdout_path=None, timeout=1800):
    """Jalankan argv tanpa shell. stdout/stdin dapat diarahkan ke berkas. Return (rc, stderr_tail)."""
    fin = open(stdin_path, "rb") if stdin_path else None
    fout = open(stdout_path, "wb") if stdout_path else subprocess.DEVNULL
    try:
        p = subprocess.run(cmd, stdin=fin, stdout=fout, stderr=subprocess.PIPE, timeout=timeout,
                           shell=False)
        return p.returncode, (p.stderr or b"").decode("utf-8", "ignore")[-400:]
    except FileNotFoundError:
        return 127, f"perintah tidak ditemukan: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timeout setelah {timeout} detik"
    finally:
        if fin:
            fin.close()
        if stdout_path:
            fout.close()


def _fmt(obj, vars_):
    if isinstance(obj, str):
        for k, v in vars_.items():
            obj = obj.replace("{" + k + "}", str(v))
        return obj
    if isinstance(obj, list):
        return [_fmt(x, vars_) for x in obj]
    if isinstance(obj, dict):
        return {k: _fmt(v, vars_) for k, v in obj.items()}
    return obj


def expand_preset(cfg):
    """Daftar langkah dari `steps:` atau preset postgres-docker."""
    if cfg.get("preset") == "postgres-docker":
        c, u = cfg["container"], cfg["user"]
        steps = []
        for db in cfg.get("databases", []):
            steps.append({
                "name": f"postgres {db}",
                "backup": {"cmd": ["docker", "exec", c, "pg_dump", "-U", u, "-Fc", db],
                           "stdout_to": "{dir}/" + db + ".dump"},
                "restore": {"cmd": ["docker", "exec", "-i", c, "pg_restore", "-U", u, "-d", db,
                                    "--clean", "--if-exists", "--no-owner", "--single-transaction"],
                            "stdin_from": "{dir}/" + db + ".dump"},
            })
        return steps
    return list(cfg.get("steps", []))


def backup(cfg, outdir, runner=default_runner):
    """Jalankan semua langkah backup. Return manifest. Raise SnapshotError bila ada yang gagal."""
    steps = expand_preset(cfg)
    if not steps:
        raise SnapshotError("snapshot dikonfigurasi tetapi tidak ada langkah (steps/preset kosong).")
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    vars_ = {"dir": str(outdir).replace("\\", "/")}
    timeout = int(cfg.get("timeout_seconds", 1800))
    manifest = {"created": time.strftime("%Y-%m-%dT%H:%M:%S"), "dir": vars_["dir"],
                "timeout_seconds": timeout, "keep": bool(cfg.get("keep", False)), "steps": []}
    for s in steps:
        b = _fmt(s["backup"], vars_)
        out = b.get("stdout_to")
        rc, err = runner(b["cmd"], None, out, timeout)
        if rc != 0:
            raise SnapshotError(f"backup '{s['name']}' gagal (rc={rc}): {err.strip()[-200:]}")
        if out and (not Path(out).exists() or Path(out).stat().st_size == 0):
            raise SnapshotError(f"backup '{s['name']}' menghasilkan berkas kosong: {out}")
        manifest["steps"].append({"name": s["name"], "file": out,
                                  "bytes": Path(out).stat().st_size if out else None,
                                  "restore": _fmt(s["restore"], vars_)})
    return manifest


def save_manifest(manifest, path):
    Path(path).write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


def load_manifest(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def restore(manifest, runner=default_runner):
    """Pulihkan semua langkah. Return daftar (nama, ok, catatan); tidak berhenti di kegagalan pertama."""
    timeout = int(manifest.get("timeout_seconds", 1800))
    out = []
    for s in manifest["steps"]:
        r = s["restore"]
        rc, err = runner(r["cmd"], r.get("stdin_from"), None, timeout)
        out.append((s["name"], rc == 0,
                    "dipulihkan" if rc == 0 else f"gagal (rc={rc}): {err.strip()[-160:]}"))
    return out


def cleanup(manifest):
    for s in manifest["steps"]:
        if s.get("file"):
            Path(s["file"]).unlink(missing_ok=True)


def restore_entry(entry, runner=default_runner):
    """Dipakai `audit.py rollback`: pulihkan dari manifest yang tercatat di jurnal."""
    mp = entry["action"]["snapshot_manifest"]
    if not Path(mp).exists():
        return False, f"manifest tidak ditemukan: {mp} — pulihkan manual"
    manifest = load_manifest(mp)
    res = restore(manifest, runner)
    ok = all(r[1] for r in res)
    if ok and not manifest.get("keep"):
        cleanup(manifest)
    return ok, "; ".join(f"{n}: {note}" for n, _ok, note in res)


class Guard:
    """Context manager: backup -> (scan) -> restore (selalu, termasuk saat scan gagal)."""

    def __init__(self, snap_cfg, reports_dir, label, runner=default_runner, echo=print):
        self.cfg, self.reports, self.label = snap_cfg, Path(reports_dir), label
        self.runner, self.echo = runner, echo
        self.active = bool(snap_cfg)
        self.ok = True
        self.manifest = None
        self.results = []

    def __enter__(self):
        if not self.active:
            return self
        outdir = self.reports / "snapshots" / time.strftime("%Y%m%d-%H%M%S")
        self.echo(f"== Snapshot data sebelum {self.label} ==")
        self.manifest = backup(self.cfg, outdir, self.runner)         # SnapshotError membatalkan scan
        mpath = outdir / "manifest.json"
        save_manifest(self.manifest, mpath)
        for s in self.manifest["steps"]:
            self.echo(f"  ok  {s['name']} ({(s['bytes'] or 0) / 1_048_576:.1f} MB)")
        self._entry = _rollback.record(self.reports, {
            "label": f"snapshot: pulihkan data ({self.label})", "module": "snapshot",
            "action": {"snapshot_manifest": str(mpath)}})
        return self

    def __exit__(self, exc_type, exc, tb):
        if not self.active or self.manifest is None:
            return False
        # Idempoten: modul yang dijalankan DI DALAM guard (mis. audit.py mass-assignment) memanggil
        # mod_rollback di akhirnya, yang ikut memproses entri snapshot pending ini lalu menghapus
        # berkas dump. Bila entri sudah done, jangan memulihkan lagi (berkasnya sudah tiada).
        entry = next((e for e in _rollback.load(self.reports)
                      if e.get("label") == self._entry.get("label")), None)
        if entry and entry.get("done"):
            self.echo(f"== Data setelah {self.label} sudah dipulihkan oleh rollback bawaan ==")
            self.ok, self.results = True, []
            return False
        self.echo(f"== Memulihkan data setelah {self.label} ==")
        self.results = restore(self.manifest, self.runner)
        for n, ok, note in self.results:
            self.echo(f"  {C.good('ok') if ok else C.bad('XX')} {n}  {note}")
        self.ok = all(r[1] for r in self.results)
        if self.ok:
            data = _rollback.load(self.reports)
            for e in data:
                if e.get("label") == self._entry.get("label") and not e.get("done"):
                    e["done"] = True
            _rollback._write(self.reports, data)
            if not self.manifest.get("keep"):
                cleanup(self.manifest)
        else:
            self.echo("PERINGATAN: pemulihan data tidak lengkap — jalankan `python audit.py rollback` "
                      "atau pulihkan manual dari berkas snapshot.")
        return False
