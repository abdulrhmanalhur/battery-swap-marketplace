"""Root-only fixed initial Atlas source registration; no runtime/gateway activation.

A new project is imported once under the installed workflow activation lock.
Normal changes subsequently use the existing source workflow, never this importer.
No credentials, user paths, shell commands or other project changes are accepted.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

STATE = Path("/var/lib/devhub-source-workflow")
REGISTRY = Path("/etc/devhub-source-workflow/projects.json")
SOURCE = Path("/opt/batteryswap-atlas-mcp")
SERVICE = "batteryswap-atlas-monitor.service"
FILES = frozenset(("atlas_monitor.py", "server.py", "owner_auth.py", "http_server.py"))


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",", ":"),ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def protected(path, file=False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Invalid administrator path")
    for part in (path,*path.parents):
        info=part.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
            raise ValueError("Administrator path is not protected")
    info=path.lstat()
    if file and (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1):
        raise ValueError("Administrator file is not regular")
    return path


def load_admin(name,path):
    import types
    data=protected(path,file=True).read_bytes()
    if len(data)>2*1024*1024:raise ValueError("Administrator module too large")
    module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
    exec(compile(data,str(path),"exec"),module.__dict__)
    return module


def proposed(registry, git_commit):
    if registry.get("schema_version")!=1 or "atlas-monitor" in registry.get("projects",{}):
        raise ValueError("Atlas registration already exists; preserve and inspect")
    if not re.fullmatch(r"[0-9a-f]{40}",git_commit):raise ValueError("Invalid source commit")
    result=json.loads(json.dumps(registry))
    for entry in result["projects"].values():
        root=entry.get("source_root")
        if root and (Path(root)==SOURCE or Path(root) in SOURCE.parents or SOURCE in Path(root).parents):
            raise ValueError("Existing source overlap")
    result["projects"]["atlas-monitor"]={
        "id":"atlas-monitor","display_name":"BatterySwap Atlas read-only MCP",
        "kind":"application","drive_entries":["Battery-Swap-V2"],
        "source_root":str(SOURCE),"source_verified":True,"provider":"python-systemd",
        "source_policy":{"include_files":sorted(FILES),"include_dirs":[],
            "exclude_names":[".git",".env*",".venv","__pycache__","data","logs","backups",
                             "*credential*","*token*","*.key","*.pem","deploy","requirements.txt"]},
        "instruction_policy":{"files":["AGENTS.md"]},
        "provider_policy":{"service":SERVICE,"health_url":"http://127.0.0.1:8017/health",
                           "health_json_key":"ok","health_json_value":True},
        "lock_path":str(STATE/"atlas-monitor"/"lock"),
        "readiness":{"snapshot":True,"publish":False,
            "reason":"Source and fixed service policy registered; enable only after credential-loaded runtime health verification"},
        "build_policy":{"execution":"local","heavy_builds":"local-only","signing":"not-applicable"},
        "configuration_epoch":os.urandom(32).hex(),
        "evidence":{"initial_git_source":{"repository":"abdulrhmanalhur/battery-swap-marketplace",
            "commit":git_commit,"path":"plugins/battery-swap-mcps/services/atlas-monitor"}}
    }
    return result


def read_bundle(bundle_id):
    if not re.fullmatch(r"[0-9a-f]{64}",bundle_id):raise ValueError("Invalid bundle identity")
    folder=protected(STATE/"imports"/("atlas-"+bundle_id))
    manifest=json.loads(protected(folder/"manifest.json",file=True).read_bytes())
    if digest(canonical(manifest))!=bundle_id:raise ValueError("Bundle identity mismatch")
    if manifest.get("project")!="atlas-monitor" or set(manifest.get("sources",{}))!=FILES|{"AGENTS.md"}:
        raise ValueError("Unexpected initial source scope")
    sources={}
    for name,record in manifest["sources"].items():
        path=protected(folder/"source"/name,file=True)
        data=path.read_bytes()
        if len(data)!=record["bytes"] or digest(data)!=record["sha256"] or len(data)>1024*1024:
            raise ValueError("Frozen source mismatch")
        sources[name]=data
    return folder,manifest,sources


def execute(action,bundle_id):
    if os.name!="posix" or os.geteuid()!=0:raise ValueError("Root administrator required")
    protected(Path(__file__),file=True)
    installer=load_admin("atlas_registration_installer",STATE/"lib/install.py")
    with installer.activation_lock():
        core=load_admin("atlas_registration_core",STATE/"lib/source_workflow.py")
        engine=core.Engine()
        folder,manifest,sources=read_bundle(bundle_id)
        before=protected(REGISTRY,file=True).read_bytes()
        if json.loads(before)!=engine.registry:raise ValueError("Registry advanced")
        proposal=proposed(engine.registry,manifest["git_commit"])
        engine.registry=proposal;engine._validate_registry()
        if os.path.lexists(SOURCE):raise ValueError("Source destination exists; refuse overwrite")
        if action=="check":
            return {"verified":True,"project":"atlas-monitor","source_files":sorted(FILES),
                    "other_registry_entries_preserved":True,"source_written":False,"publication_enabled":False}
        proof=folder/"registration.json"
        if os.path.lexists(proof):raise ValueError("Registration has prior journal; do not retry")
        installer.atomic_bytes(folder/"registry.before.json",before,0o600)
        installer.atomic_bytes(folder/"registry.proposed.json",canonical(proposal)+b"\n",0o600)
        installer.atomic_bytes(proof,canonical({"phase":"prepared","bundle_id":bundle_id,
            "before_sha256":digest(before)})+b"\n",0o600)
        SOURCE.mkdir(mode=0o755)
        for name,data in sources.items():installer.atomic_bytes(SOURCE/name,data,0o644)
        # Revalidate the exact imported source and read-only instructions under the
        # global activation exclusion before the one-record metadata CAS.
        observed,contents=engine._source("atlas-monitor")
        if set(contents)!=FILES or any(contents[name]!=sources[name] for name in FILES):
            raise ValueError("Imported source verification rejected; preserve journal")
        engine._instruction_source("atlas-monitor")
        if REGISTRY.read_bytes()!=before:raise ValueError("Registry changed before CAS")
        installer.atomic_bytes(REGISTRY,canonical(proposal)+b"\n",0o644)
        if json.loads(REGISTRY.read_bytes())!=proposal:raise ValueError("Registration verification failed")
        installer.atomic_bytes(proof,canonical({"phase":"committed","bundle_id":bundle_id,
            "before_sha256":digest(before),"after_sha256":digest(canonical(proposal)+b"\n"),
            "source_manifest_sha256":digest(core.canonical(observed)),"publication_enabled":False})+b"\n",0o600)
        return {"registered":True,"project":"atlas-monitor","other_registry_entries_preserved":True,
                "publication_enabled":False,"service_started":False,"credential_contents_read":False,
                "backup":str(folder/"registry.before.json")}


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("action",choices=("check","register"));parser.add_argument("bundle_id")
    args=parser.parse_args()
    try:print(json.dumps(execute(args.action,args.bundle_id),sort_keys=True))
    except Exception:
        print(json.dumps({"ok":False,"error":"Atlas registration refused; preserve journal and inspect; do not retry automatically"}))
        raise SystemExit(2)
