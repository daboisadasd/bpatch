"""
bpatch exception hierarchy.

All internal errors raise BpatchError subclasses instead of calling sys.exit().
Only bpatch.cli.main() catches these and converts them to exit-code 1.
This makes every function safe to call from tests or library code.
"""


class BpatchError(Exception):
    """Base class for all bpatch errors."""


class BpatchToolchainError(BpatchError):
    """Could not locate or resolve a required toolchain component."""


class BpatchCompileError(BpatchError):
    """Payload compilation or linking failed."""


class BpatchFormatError(BpatchError):
    """Binary format is unsupported or could not be detected."""


class BpatchInjectError(BpatchError):
    """Injection-time error (bad address, no room in header, etc.)."""


class BpatchSymbolError(BpatchError):
    """Symbol lookup failed."""
