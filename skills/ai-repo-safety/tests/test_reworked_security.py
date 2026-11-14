"""Regression checks for observable safety boundaries; no live scanners/network."""
import json
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest
from ai_repo_safety.cli import main
from ai_repo_safety.results import ScanReport, ToolRun
from ai_repo_safety.secret_scan import trufflehog_flags, safe_trufflehog_output
from ai_repo_safety import scanner, scan_output


def test_verification_requires_opt_in_and_cannot_be_offline():
    assert '--no-verification' in trufflehog_flags()
    assert '--no-verification' in trufflehog_flags(offline=True)
    assert '--no-verification' not in trufflehog_flags(verify_secrets=True)
    with pytest.raises(ValueError):
        trufflehog_flags(offline=True, verify_secrets=True)
    with pytest.raises(SystemExit) as exc:
        main(['scan', '--offline', '--verify-secrets'])
    assert exc.value.code == 2


def test_secret_scanner_never_relays_raw_values_or_errors():
    canary='SYNTHETIC_PRIVATE_CANARY'
    code,out,err=safe_trufflehog_output(0,json.dumps({'Raw':canary,'Verified':False}),canary)
    assert code != 0
    assert '1 finding' in out
    assert canary not in out+err
    assert safe_trufflehog_output(0,'not-json '+canary,canary)[0] != 0


def test_text_offline_scan_blocks_secret_and_redacts_output(tmp_path,capsys):
    seen=[]
    def run(cmd, **kwargs):
        seen.append(cmd)
        return 183,json.dumps({'Raw':'SYNTHETIC_PRIVATE_CANARY'}),'SYNTHETIC_PRIVATE_CANARY'
    with patch.object(scanner,'which',side_effect=lambda n: '/fake' if n=='trufflehog' else None), patch.object(scanner,'git_has_commits',return_value=False), patch.object(scanner,'run_cmd',side_effect=run):
        code=scanner.scan(tmp_path,offline=True)
    assert code==1
    assert '--no-verification' in next(c for c in seen if c[0]=='trufflehog')
    assert 'SYNTHETIC_PRIVATE_CANARY' not in capsys.readouterr().out


def test_sast_findings_block_both_text_and_json(tmp_path,capsys):
    rules=tmp_path/'.repo-safety/opengrep';rules.mkdir(parents=True)
    seen=[]
    def run(cmd,**kw):
        seen.append(cmd)
        return 1,'finding',''
    with patch.object(scanner,'which',side_effect=lambda n: '/fake' if n=='opengrep' else None), patch.object(scanner,'git_has_commits',return_value=False), patch.object(scanner,'run_cmd',side_effect=run):
        assert scanner.scan(tmp_path,offline=True)==1
    assert '--error' in next(c for c in seen if c[0]=='opengrep')
    def subprocess(cmd,**kw):
        return CompletedProcess(cmd,1,'finding','')
    capsys.readouterr()
    with patch.object(scanner,'which',side_effect=lambda n:'/fake' if n=='opengrep' else None), patch.object(scanner,'git_has_commits',return_value=False), patch.object(scanner,'run_cmd',side_effect=run):
        assert scan_output.emit_scan(tmp_path,offline=True)==1
    report=json.loads(capsys.readouterr().out)
    assert any(t['name']=='opengrep' and t['status']=='failed' for t in report['tools'])


def test_tool_failures_are_not_successful_reports():
    assert ScanReport(status='failed',target='.',tools=[ToolRun(name='sast',command=[],status='failed')]).exit_code()==1
    assert ScanReport(status='error',target='.',tools=[ToolRun(name='sast',command=[],status='error')]).exit_code()==2


def test_installer_does_not_resolve_nonexistent_npm_or_unverified_binary(capsys):
    from ai_repo_safety import tools
    calls=[]
    with patch.object(tools,'which',side_effect=lambda n: '/fake' if n=='uv' else None), patch.object(tools,'is_windows',return_value=True), patch.object(tools,'run_cmd',side_effect=lambda cmd,**kw:(calls.append(cmd) or (0,'',''))):
        assert tools.install_missing_tools(yes=True)!=0
    assert not any('@opengrep/cli' in str(c) for c in calls)
    assert 'signed checksums' in capsys.readouterr().out


def test_worktree_and_core_hookspath_are_supported(tmp_path):
    import subprocess
    from ai_repo_safety.hooks import install_hooks
    def git(*args):
        return subprocess.run(['git',*args],cwd=tmp_path,check=True,capture_output=True,text=True)
    git('init','-q');git('-c','user.name=Test','-c','user.email=test@example.invalid','commit','--allow-empty','-m','initial')
    worktree=tmp_path/'tree'
    git('worktree','add','--detach',str(worktree))
    assert (worktree/'.git').is_file()
    assert install_hooks(worktree)==0
    git('config','core.hooksPath','.custom-hooks')
    assert install_hooks(tmp_path)==0
    assert (tmp_path/'.custom-hooks/pre-commit').is_file()


@pytest.mark.parametrize("marker,tool,online",[("package.json","eslint",False),("go.mod","gosec",False),("Cargo.toml","cargo-audit",True)])
def test_language_failures_match_all_formats(tmp_path,capsys,marker,tool,online):
    (tmp_path/marker).write_text('{}' if marker.endswith('json') else '')
    with patch.object(scanner,'which',return_value='/fake'), patch.object(scanner,'git_has_commits',return_value=False), patch.object(scanner,'run_cmd',side_effect=lambda cmd,**kw:(1 if (cmd[0]==tool or (tool=='cargo-audit' and cmd[:2]==['cargo','audit'])) else 0,'','')):
        text=scanner.scan(tmp_path,offline=not online)
        capsys.readouterr()
        structured=scan_output.emit_scan(tmp_path,offline=not online)
        payload=json.loads(capsys.readouterr().out)
        sarif=scan_output.emit_scan(tmp_path,offline=not online,sarif=True)
        result=json.loads(capsys.readouterr().out)
    assert text==structured==sarif==1
    assert any(t['status']=='failed' for t in payload['tools'])
    assert not result['runs'][0]['invocations'][0]['executionSuccessful']


def test_new_repo_fast_scan_and_no_target_helper_execution(tmp_path,capsys):
    (tmp_path/'.env').write_text('APP_NAME=synthetic_canary')
    malicious=tmp_path/'.repo-safety/scripts';malicious.mkdir(parents=True)
    sentinel=tmp_path/'executed'
    (malicious/'forbid_sensitive_files.py').write_text(f'open({str(sentinel)!r},"w").write("bad")')
    with patch.object(scanner,'which',return_value=None),patch.object(scanner,'git_has_commits',return_value=False):
        assert scanner.scan(tmp_path,offline=True)==1
        capsys.readouterr()
        assert scan_output.emit_scan(tmp_path,offline=True)==1
    assert not sentinel.exists()
    assert 'synthetic_canary' not in capsys.readouterr().out
