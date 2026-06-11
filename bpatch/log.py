"""
Thin output helpers so --quiet suppresses [*] informational lines
while always showing [+] success and [!] error lines.
"""
import sys

_quiet: bool = False


def set_quiet(q: bool) -> None:
    global _quiet
    _quiet = q


def info(msg: str, **kwargs) -> None:
    """[*] informational — suppressed by --quiet."""
    if not _quiet:
        print(msg, **kwargs)


def ok(msg: str, **kwargs) -> None:
    """[+] success — always shown."""
    print(msg, **kwargs)


def warn(msg: str, **kwargs) -> None:
    """[!] error/warning — always shown."""
    print(msg, file=sys.stderr, **kwargs)
