#!/usr/bin/env python3
"""Read-only, bounded intake heuristics. Never executes repository code or emits values."""
from __future__ import annotations
import argparse, ast, base64, json, os, re, subprocess
from pathlib import Path

LIMIT=1_000_000
MAX_FILES=5000
SKIP={'.git','node_modules','.venv','venv','__pycache__','vendor','dist','build'}
SENSITIVE=re.compile(r'(?i)(^|/)(\.env($|\.)|id_(rsa|ed25519)$|credentials($|\.)|[^/]*\.(pem|p12|pfx|key)$)')
CONFIG=re.compile(rb'(?im)(?:^|[\n\r;])\s*(?:[A-Z_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY|DATABASE_URL)[A-Z_]*)\s*[:=]\s*[^\s]{4,}')
MEDIA=re.compile(r'(?i)[\w./-]+\.(?:png|jpe?g|webp|gif|svg|pdf|mp4)(?:\b|$)')
SECRET_WORD=re.compile(r'(?i)(\.env\b|private.?key|credential|api.?key|secret|password|токен|парол)')
ACTION=re.compile(r'(?i)(provenance|canary|base64|byte.?for.?byte|encode|integer|tuple|\bbytes\b|закод|побайт)')

def instruction(path):
    p=path.lower()
    return Path(p).name in {'agents.md','claude.md','gemini.md','skill.md','copilot-instructions.md'} or p.startswith(('.cursor/rules/','.github/instructions/','.agents/skills/','.claude/'))

def encoded_findings(content):
    try: tree=ast.parse(content)
    except (SyntaxError, ValueError, RecursionError): return []
    found=[]
    for node in ast.walk(tree):
        data=None
        if isinstance(node,(ast.Tuple,ast.List)) and 32<=len(node.elts)<=LIMIT:
            if all(isinstance(x,ast.Constant) and type(x.value) is int and 0<=x.value<=255 for x in node.elts):
                data=bytes(x.value for x in node.elts)
        elif isinstance(node,ast.Constant) and isinstance(node.value,str) and 32<=len(node.value)<=LIMIT:
            try: data=base64.b64decode(node.value,validate=True)
            except (ValueError,TypeError): pass
        if data and CONFIG.search(data): found.append((getattr(node,'lineno',1),'encoded-sensitive-config'))
    return sorted(set(found))

def inspect(root: Path, staged=False):
    root=root.resolve(); findings=[]; incomplete=[]; total=0
    def add(path,line,kind): findings.append({'path':path,'line':line,'category':kind})
    if staged:
        def git(*args):
            return subprocess.run(['git','--literal-pathspecs','--no-optional-locks','-C',str(root),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=30).stdout
        raw=git('diff','--cached','--name-only','--diff-filter=ACMR','-z')
        names=raw.decode('utf-8',errors='surrogateescape').split('\0')
        def read(name):
            entry=git('ls-files','--stage','-z','--',name).split(b'\0')[0]
            if not entry: raise ValueError('missing indexed entry')
            mode,oid,stage=entry.split(b'\t',1)[0].split()
            if mode not in {b'100644',b'100755'}: raise ValueError('nonregular indexed entry')
            if int(git('cat-file','-s',oid.decode()))>LIMIT: raise ValueError('oversize')
            return git('cat-file','blob',oid.decode())
    else:
        names=[]
        for current,dirs,files in os.walk(root,followlinks=False):
            dirs[:]=[d for d in dirs if d not in SKIP and not (Path(current)/d).is_symlink()]
            for file in files:
                names.append(str((Path(current)/file).relative_to(root)))
                if len(names)>MAX_FILES: break
            if len(names)>MAX_FILES: break
        def read(name):
            p=root/name
            if p.is_symlink() or not p.resolve().is_relative_to(root): raise ValueError('symlink')
            if not p.is_file() or p.stat().st_size>LIMIT: raise ValueError('nonregular or oversize')
            # O_NOFOLLOW prevents following a final symlink swapped after the check.
            fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
            with os.fdopen(fd,'rb') as f: return f.read(LIMIT+1)
    if len(names)>MAX_FILES: incomplete.append('file-count-limit')
    for name in names[:MAX_FILES]:
        if not name: continue
        total+=1
        if SENSITIVE.search(name):
            add(name,0,'sensitive-file-not-read');continue
        if not (instruction(name) or Path(name).suffix.lower() in {'.py','.md','.txt','.json','.yaml','.yml','.toml','.sh','.js','.ts'}): continue
        try:
            data=read(name)
            if len(data)>LIMIT: raise ValueError('oversize')
            content=data.decode('utf-8')
        except (OSError,ValueError,UnicodeError,subprocess.SubprocessError):
            incomplete.append(name);continue
        if instruction(name):
            for number,line in enumerate(content.splitlines(),1):
                if MEDIA.search(line): add(name,number,'linked-media-needs-review')
                if SECRET_WORD.search(line) and ACTION.search(line): add(name,number,'secret-transformation-instruction')
        if Path(name).suffix.lower()=='.py':
            for number,category in encoded_findings(content):add(name,number,category)
    needs=any(f['category']!='sensitive-file-not-read' for f in findings)
    return {'status':'needs-review' if needs or incomplete else 'no-heuristic-findings','mode':'staged' if staged else 'working-tree','files_considered':total,'findings':findings,'uninspected':incomplete,'coverage':'Bounded text/Python heuristics; media, other encodings and languages require review. No clean bill of health.'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--staged',action='store_true');a=p.parse_args()
    if not a.root.is_dir():p.error('root must be an existing directory')
    try: result=inspect(a.root,a.staged)
    except (OSError,ValueError,subprocess.SubprocessError):
        print(json.dumps({'status':'error','reason':'repository metadata unavailable; no secret values printed'}));return 2
    print(json.dumps(result,ensure_ascii=True,indent=2));return int(result['status']=='needs-review')
if __name__=='__main__':raise SystemExit(main())
