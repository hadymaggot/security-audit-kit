"""Unit test modul captcha — murni, tanpa jaringan."""
import base64
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CP = _load("run_captcha_t", "tests/captcha/run_captcha.py")
RP = _load("report_cp_t", "report.py")


def _b64(svg):
    return base64.b64encode(svg.encode()).decode()


def _challenge(x=237, y=33, leak=True, extra=None):
    bg = (f'<svg viewBox="0 0 320 140"><rect width="320" height="140"/>'
          + (f'<g transform="translate({x},{y})"><path d="M0 0"/></g>' if leak else
             '<g transform="translate(0,0)"><path d="M0 0"/></g>') + "</svg>")
    pc = (f'<svg viewBox="0 0 50 50"><g clip-path="url(#c)">'
          + (f'<g transform="translate(-{x},-{y})"><rect/></g>' if leak else "<rect/>")
          + "</g></svg>")
    d = {"captcha_key": "K1", "background": _b64(bg), "puzzle_piece": _b64(pc),
         "y_position": y, "image_width": 320, "image_height": 140, "piece_size": 50}
    d.update(extra or {})
    return d


# ── kunci jawaban ───────────────────────────────────────────────────────────
def test_kunci_jawaban_eksplisit_terdeteksi():
    rows = {r["check"]: r for r in CP.analyze_challenge({"answer": 120, "image_width": 320})}
    assert rows["kunci jawaban di response"]["ok"] is False
    assert "answer=120" in rows["kunci jawaban di response"]["note"]
    assert CP.find_answer_keys({"target_x": 10, "x_position": 4})
    assert not CP.find_answer_keys({"y_position": 33, "image_width": 320, "piece_size": 50,
                                    "captcha_key": "ABC"})                   # bukan jawaban


# ── SVG translate ───────────────────────────────────────────────────────────
def test_translate_membocorkan_posisi():
    rows = {r["check"]: r for r in CP.analyze_challenge(_challenge(237, 33))}
    r = rows["SVG expose posisi target"]
    assert r["ok"] is False and r["x"] == 237 and r["kind"] == "captcha-answer-leak"
    assert "translate(-237,-33)" in r["note"] and "translate(237,33)" in r["note"]
    assert "y_position" in r["note"]


def test_tanpa_offset_tak_ada_false_positive():
    rows = {r["check"]: r for r in CP.analyze_challenge(_challenge(leak=False))}
    assert rows["SVG expose posisi target"]["ok"] is True
    assert rows["kunci jawaban di response"]["ok"] is True


def test_translate_di_luar_lebar_gambar_diabaikan():
    rows = {r["check"]: r for r in CP.analyze_challenge(_challenge(x=999, y=33))}
    assert rows["SVG expose posisi target"]["ok"] is True       # 999 > image_width 320


def test_decode_svg_layers_data_uri_dan_mentah():
    d = {"a": "data:image/svg+xml;base64," + _b64("<svg><g transform='translate(-5,-6)'/></svg>"),
         "b": "<svg><g transform='translate(1,2)'/></svg>" + " " * 40, "c": "bukan svg " * 10}
    layers = CP.decode_svg_layers(d)
    assert set(layers) == {"a", "b"}
    assert CP.translates(layers["a"]) == [(-5.0, -6.0)]


def test_y_cocok_dengan_field_walau_lapisan_lain_tak_ada():
    pc = _b64('<svg><g transform="translate(-50,-33)"/></svg>')
    d = {"puzzle_piece": pc, "y_position": 33, "image_width": 320}
    leaks = CP.find_translate_leak(CP.decode_svg_layers(d), d)
    assert leaks and leaks[0]["x"] == 50 and leaks[0]["y_position"] is True


# ── keacakan ────────────────────────────────────────────────────────────────
def test_keacakan_posisi():
    assert CP.evaluate_randomness([95]) is None
    tetap = CP.evaluate_randomness([95, 95, 95])
    assert tetap["ok"] is False and "tidak acak" in tetap["note"]
    acak = CP.evaluate_randomness([95, 164])
    assert acak["ok"] is True and "bervariasi" in acak["note"]


# ── run dengan session palsu ────────────────────────────────────────────────
class _R:
    def __init__(self, body, status=200):
        self._b, self.status_code = body, status

    def json(self):
        return self._b


class _S:
    def __init__(self, bodies):
        self.bodies, self.verify = list(bodies), True

    def request(self, method, url, **kw):
        return _R({"success": True, "data": self.bodies.pop(0)})


def test_run_dua_sampel_dengan_kebocoran():
    cfg = {"base_url": "http://t", "samples": 2}
    rows = CP.run(cfg, sess=_S([_challenge(95), _challenge(164)]))
    by = {r["check"]: r for r in rows}
    assert by["SVG expose posisi target"]["ok"] is False
    assert by["posisi target tetap antar tantangan"]["ok"] is True
    assert all(r["url"].startswith("GET http://t/api/captcha") for r in rows)


def test_run_endpoint_error_melempar():
    class _E(_S):
        def request(self, *a, **k):
            return _R({}, 500)
    try:
        CP.fetch({"base_url": "http://t"}, sess=_E([]))
        assert False, "harus melempar"
    except RuntimeError as exc:
        assert "HTTP 500" in str(exc)


# ── integrasi report ────────────────────────────────────────────────────────
def test_report_memuat_captcha(tmp_path):
    rows = CP.analyze_challenge(_challenge(237, 33))
    (tmp_path / "captcha.json").write_text(json.dumps(
        {"module": "captcha", "failures": 1, "results": rows}), encoding="utf-8")
    gagal = [x for x in RP.collect(tmp_path) if not x["lulus"]]
    assert gagal and gagal[0]["kind"] == "captcha-answer-leak" and gagal[0]["severity"] == "medium"
    assert RP.cvss_for("captcha-answer-leak", "medium")[0] == 5.3
    assert "captcha-answer-leak" in RP.KIND_LABEL
