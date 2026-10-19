"""OWNER RUNS INTERACTIVELY AFTER APPROVAL; assistant must never execute this."""
import getpass
import os
import stat
import sys
import warnings
from pathlib import Path

NAMES={"mongodb-uri","github-client-id","github-client-secret"}
def main():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise SystemExit("SECURE_TTY_REQUIRED")
    if len(sys.argv)!=2 or sys.argv[1] not in NAMES or os.geteuid()!=0:
        raise SystemExit("ROOT_AND_APPROVED_CREDENTIAL_NAME_REQUIRED")
    folder=Path("/etc/batteryswap-mongo-read")
    folder.mkdir(mode=0o700,parents=False,exist_ok=True)
    info=folder.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
        raise SystemExit("PRIVATE_DIRECTORY_PERMISSIONS_REQUIRED")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error",getpass.GetPassWarning)
            value=getpass.getpass("Private value (hidden; do not paste in chat): ")
    except (getpass.GetPassWarning,EOFError,OSError):
        raise SystemExit("SECURE_TTY_REQUIRED") from None
    if not value or len(value.encode())>8192 or any(c in value for c in "\r\n\0"):
        raise SystemExit("PRIVATE_VALUE_REJECTED")
    try:value.encode("ascii")
    except UnicodeError:raise SystemExit("PRIVATE_VALUE_REJECTED") from None
    path=folder/sys.argv[1]
    # New files only. Existing values are never read, printed, followed or overwritten.
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w") as stream:
        stream.write(value)
        stream.flush();os.fsync(stream.fileno())
    print("Private credential saved; value not displayed.")
if __name__=="__main__":main()
