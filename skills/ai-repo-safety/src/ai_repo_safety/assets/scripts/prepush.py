#!/usr/bin/env python3
"""Generated local-fork launcher; configured during init."""
import runpy
import sys
from pathlib import Path
launcher = Path("__BUNDLED_LAUNCHER__")
if not launcher.is_file():
    raise SystemExit("Bundled repo-safety launcher is unavailable; run init again")
sys.argv = [str(launcher), "prepush", "--target", str(Path.cwd()), *sys.argv[1:]]
runpy.run_path(str(launcher), run_name="__main__")
