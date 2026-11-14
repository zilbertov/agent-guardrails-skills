from pathlib import Path
import runpy
launcher = Path(__BUNDLED_LAUNCHER__)
if not launcher.is_file():
    raise SystemExit("Bundled fork missing; reinstall from reviewed source")
runpy.run_path(str(launcher),run_name="__main__")
