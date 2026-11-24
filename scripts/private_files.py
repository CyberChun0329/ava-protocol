"""Project-confined private-file reads shared by encrypted custody adapters."""
import os
from pathlib import Path
import stat

# Only the trusted process host supplies this environment override. Requests cannot change it.
ROOT = (Path(os.environ["AVA_CUSTODY_ROOT"]).resolve() if "AVA_CUSTODY_ROOT" in os.environ
        else Path(__file__).resolve().parents[1])


def project_path(value):
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    if ".." in path.parts or not path.is_relative_to(ROOT):
        raise ValueError("path must stay inside this project")
    for parent in (path, *path.parents):
        if parent == ROOT:
            break
        if parent.is_symlink():
            raise ValueError("symlink paths are forbidden")
    return path


def private_bytes(path, limit=1024 * 1024):
    path = project_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit):
            raise ValueError("unsafe private file")
        return stream.read(limit + 1)

