"""Local, bounded, no-follow filesystem support; Python 3.12 standard library."""
import argparse
from contextlib import contextmanager
import functools
import json
import os
import stat

class InputError(Exception):
    pass

class Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("formatter_class", argparse.ArgumentDefaultsHelpFormatter)
        super().__init__(*args, **kwargs)
    def add_argument(self, *args, **kwargs):
        if args and str(args[0]).startswith("--") and "default" in kwargs and "help" not in kwargs:
            kwargs["help"] = "Selected policy or resource bound."
        return super().add_argument(*args, **kwargs)
    def error(self, message):
        raise InputError("invalid command-line arguments; use --help")

def positive(value):
    try:
        n = int(value)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError("expected a positive integer") from None
    if n <= 0:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return n

def limits(**values):
    for key, value in values.items():
        if type(value) is not int or value <= 0:
            raise InputError("limits must be positive integers")
    if values.get("max_depth", 1) > 128:
        raise InputError("maximum supported depth is 128")

class Report:
    def __init__(self, tool, max_findings=1000):
        self.tool, self.max_findings = tool, max_findings
        self.findings, self.total = [], 0
    def add(self, code, **context):
        self.total += 1
        if len(self.findings) < self.max_findings:
            self.findings.append({"code": code, **context})
    def finish(self, summary=None, **extra):
        return {"schema_version": 1, "tool": self.tool,
                "status": "findings" if self.total else "pass",
                "summary": summary or {}, "finding_count": self.total,
                "findings_truncated": self.total > len(self.findings),
                "findings": self.findings, **extra}

def error(tool, message):
    return {"schema_version": 1, "tool": tool, "status": "error",
            "error": {"code": "input_error", "message": message}}

def guarded(tool):
    def decorate(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except InputError as exc:
                return error(tool, str(exc))
            except (OSError, ValueError, TypeError, RecursionError):
                return error(tool, "input is unavailable, unsupported, changed, or malformed")
        return wrapper
    return decorate

def emit(result):
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return {"pass": 0, "findings": 1, "error": 2}[result["status"]]

def cli(tool, parse_and_audit):
    try:
        return emit(parse_and_audit())
    except InputError as exc:
        return emit(error(tool, str(exc)))

def _flags(directory=False):
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise InputError("this audit requires POSIX no-follow, descriptor-relative filesystem support")
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if directory else 0)

@contextmanager
def anchored(path, directory=False):
    # Open every path component without following symlinks, including ancestors.
    raw = os.fsdecode(os.fspath(path))
    p = raw if os.path.isabs(raw) else os.getcwd() + os.sep + raw
    parts = [x for x in p.split(os.sep) if x]
    fd = os.open(os.sep, _flags(True))
    try:
        for i, part in enumerate(parts):
            next_fd = os.open(part, _flags(directory or i < len(parts)-1), dir_fd=fd)
            os.close(fd)
            fd = next_fd
        st = os.fstat(fd)
        if not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)):
            raise InputError("expected a real directory" if directory else "expected a regular non-symlink file")
        yield fd
    finally:
        os.close(fd)

def read_fd(fd, max_bytes):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise InputError("expected a regular non-symlink file")
    if before.st_size > max_bytes:
        raise InputError("file byte limit exceeded")
    chunks, total = [], 0
    while True:
        chunk = os.read(fd, min(65536, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise InputError("file byte limit exceeded")
    after = os.fstat(fd)
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise InputError("input changed while being read")
    return b"".join(chunks)

def read_file(path, max_bytes):
    with anchored(path) as fd:
        return read_fd(fd, max_bytes)

def read_at(parent_fd, name, expected, max_bytes):
    fd = os.open(name, _flags(), dir_fd=parent_fd)
    try:
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) != (expected.st_dev, expected.st_ino, expected.st_size, expected.st_mtime_ns, expected.st_ctime_ns):
            raise InputError("input changed while being read")
        return read_fd(fd, max_bytes)
    finally:
        os.close(fd)

def walk(fd, max_entries=100000, max_depth=64):
    """Yield (relative path, lstat, parent descriptor, basename). No symlink descent."""
    limits(max_entries=max_entries, max_depth=max_depth)
    count = 0
    def visit(directory_fd, prefix, depth):
        nonlocal count
        names = []
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                if count >= max_entries:
                    raise InputError("entry limit exceeded")
                count += 1
                names.append(entry.name)
        for name in sorted(names):
            rel = prefix + name
            st = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            yield rel, st, directory_fd, name
            if stat.S_ISDIR(st.st_mode):
                if depth >= max_depth:
                    raise InputError("directory depth limit exceeded")
                child = os.open(name, _flags(True), dir_fd=directory_fd)
                try:
                    actual = os.fstat(child)
                    if (st.st_dev, st.st_ino) != (actual.st_dev, actual.st_ino):
                        raise InputError("directory changed during scan")
                    yield from visit(child, rel + "/", depth + 1)
                finally:
                    os.close(child)
    yield from visit(fd, "", 0)
