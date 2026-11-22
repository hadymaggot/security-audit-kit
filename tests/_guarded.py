#!/usr/bin/env python3
"""Run a module runner under the bug bounty guard (scope check + global rate limit).

    python tests/_guarded.py <runner.py> [runner args...]

The scope comes from the SAK_SCOPE_JSON environment variable (set by audit.py in bounty mode). It fails
closed: without a valid scope the runner is NOT started, so it can never run unthrottled by accident.
"""
from __future__ import annotations

import json
import os
import runpy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _scope  # noqa: E402
import _throttle  # noqa: E402


def main(argv):
    if len(argv) < 2:
        print("pemakaian: _guarded.py <runner.py> [argumen...]", file=sys.stderr)
        return 2
    try:
        scope = _scope.Scope.from_dict(json.loads(os.environ.get("SAK_SCOPE_JSON") or ""))
    except (ValueError, _scope.ScopeError) as exc:
        print(f"DITOLAK guard bounty: scope tidak tersedia atau tidak valid ({exc}); runner tidak dijalankan.",
              file=sys.stderr)
        return 2
    script = Path(argv[1]).resolve()
    if not script.is_file():
        print(f"runner tidak ditemukan: {script}", file=sys.stderr)
        return 2
    _throttle.install(scope)
    sys.argv = [str(script), *argv[2:]]
    sys.path.insert(0, str(script.parent))          # same import behavior as running the script directly
    runpy.run_path(str(script), run_name="__main__")  # the runner ends with sys.exit(main())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
