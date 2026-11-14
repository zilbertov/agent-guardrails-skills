"""Generated source-bundle prepush launcher integration."""
from pathlib import Path
import subprocess, sys
from ai_repo_safety.bootstrap import init_project

def test_generated_prepush_uses_fork_and_blocks_missing_scanner(tmp_path):
    subprocess.run(["git","init","-q"],cwd=tmp_path,check=True)
    assert init_project(tmp_path,python="no",github="no",gitlab="no")==0
    script=tmp_path/".repo-safety/scripts/prepush.py"
    assert "__BUNDLED_LAUNCHER__" not in script.read_text()
    proc=subprocess.run([sys.executable,str(script)],cwd=tmp_path,env={"PATH":""},capture_output=True,text=True,timeout=20)
    assert proc.returncode!=0
    assert "gitleaks" in proc.stdout+proc.stderr
