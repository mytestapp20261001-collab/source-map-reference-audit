"""Synthetic examples; all fixtures live in an automatically removed temporary directory."""
from pathlib import Path
import json, subprocess, sys, tempfile
TOOL=Path(__file__).resolve().parents[1]/"tool.py"
def run(expected,*args):
    r=subprocess.run([sys.executable,str(TOOL),*map(str,args)],capture_output=True,text=True)
    assert r.returncode==expected,(r.returncode,r.stdout,r.stderr)
    print(r.stdout.strip())
with tempfile.TemporaryDirectory() as tmp:
    p=Path(tmp)
    (p/"src.js").write_text("const synthetic = 1;\n");m=p/"bundle.map"
    m.write_text(json.dumps({"version":3,"sources":["src.js"],"names":[],"mappings":""}));run(0,m,"--root",p)
    m.write_text(json.dumps({"version":3,"sources":["missing.js"],"names":[],"mappings":""}));run(1,m,"--root",p)
