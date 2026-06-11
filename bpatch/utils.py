"""Shared low-level utilities (path resolution, alignment, deduplication)."""

import os
import platform
import shlex
import shutil
from pathlib import Path


def align_up(v: int, a: int) -> int:
    """Round *v* up to the next multiple of alignment *a*."""
    return (v + a - 1) & ~(a - 1)


def resolve_exe(candidate: str) -> str:
    """
    Resolve an executable name or path to a runnable absolute path.
    Returns '' if not found.
    """
    if not candidate:
        return ""

    p = Path(candidate)
    if p.is_file():
        return str(p)

    w = shutil.which(candidate)
    if w:
        return w

    has_sep = (os.path.sep in candidate) or (
        os.path.altsep and os.path.altsep in candidate
    )
    if has_sep and platform.system() == "Windows":
        for ext in (".exe", ".cmd", ".bat"):
            q = Path(candidate + ext)
            if q.is_file():
                return str(q)
    return ""


def resolve_near(exe_path: str, names: tuple[str, ...]) -> str:
    """
    Resolve one of *names*, preferring binaries in the same directory as *exe_path*.
    Returns '' when none are found.
    """
    base_dir = Path(exe_path).parent if exe_path else None
    for name in names:
        if base_dir:
            local = resolve_exe(str(base_dir / name))
            if local:
                return local
        found = resolve_exe(name)
        if found:
            return found
    return ""


def dedupe_keep_order(items: list[str]) -> list[str]:
    """Remove duplicates from *items* while preserving insertion order."""
    out: list[str] = []
    seen: set[str] = set()
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def parse_extra_flags(flags_raw: str) -> list[str]:
    """Split a flags string into a list, using platform-aware quoting rules."""
    if not flags_raw.strip():
        return []
    return shlex.split(flags_raw, posix=(platform.system() != "Windows"))
