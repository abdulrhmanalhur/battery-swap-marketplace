import hashlib
import re
import zipfile
from email.parser import BytesParser
from pathlib import Path
from packaging.requirements import Requirement
from packaging.markers import default_environment
from packaging.specifiers import SpecifierSet

def verify(root):
    root=Path(root)
    lines=(root/"linux-runtime-requirements.lock").read_text().splitlines()
    locked={}
    for line in lines:
        match=re.fullmatch(r"([^=]+)==([^ ]+) --hash=sha256:([0-9a-f]{64})",line)
        if not match:raise ValueError("INVALID_LOCK_LINE")
        name,version,sha=match.groups();locked[re.sub(r"[-_.]+","-",name.lower())]=(version,sha)
    found={}; metadata=[]
    for wheel in (root/"linux-wheels").glob("*.whl"):
        with zipfile.ZipFile(wheel) as archive:
            path=next(x for x in archive.namelist() if x.endswith(".dist-info/METADATA"))
            info=BytesParser().parsebytes(archive.read(path))
        name=re.sub(r"[-_.]+","-",info["Name"].lower())
        if name not in locked:raise ValueError("UNLOCKED_WHEEL")
        version,sha=locked[name]
        if info["Version"]!=version or hashlib.sha256(wheel.read_bytes()).hexdigest()!=sha:
            raise ValueError("WHEEL_HASH_OR_VERSION_MISMATCH")
        if info.get("Requires-Python") and "3.10.12" not in SpecifierSet(info["Requires-Python"]):
            raise ValueError("PYTHON_VERSION_UNSUPPORTED:"+name)
        found[name]=version;metadata.append(info)
    if set(found)!=set(locked):raise ValueError("MISSING_WHEEL")
    env=default_environment();env.update(python_version="3.10",python_full_version="3.10.12",
        sys_platform="linux",platform_system="Linux",platform_machine="x86_64",os_name="posix",extra="")
    for info in metadata:
        for text in info.get_all("Requires-Dist",[]):
            requirement=Requirement(text)
            if requirement.marker and not requirement.marker.evaluate(env):continue
            name=re.sub(r"[-_.]+","-",requirement.name.lower())
            if name not in found or found[name] not in requirement.specifier:
                raise ValueError("DEPENDENCY_CLOSURE_FAILED:"+info["Name"]+":"+name)
    return {"wheel_hashes_verified":len(found),"dependency_closure":"Linux CPython3.10 x86_64 metadata verified",
            "linux_execution":"not performed"}
if __name__=="__main__":
    import json,sys
    print(json.dumps(verify(sys.argv[1]),indent=2))
