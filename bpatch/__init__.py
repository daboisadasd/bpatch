"""bpatch — static binary injection tool for malware analysis and RE."""

__version__ = "0.4.0"

from .errors import (
    BpatchError,
    BpatchToolchainError,
    BpatchCompileError,
    BpatchFormatError,
    BpatchInjectError,
    BpatchSymbolError,
)
from .inject import inject, inject_sites
from .pattern import find_pattern_in_binary, resolve_pattern_address
from .undo import undo_elf, undo_pe

__all__ = [
    "__version__",
    # Core injection
    "inject",
    "inject_sites",
    # Pattern search
    "find_pattern_in_binary",
    "resolve_pattern_address",
    # Undo
    "undo_elf",
    "undo_pe",
    # Errors
    "BpatchError",
    "BpatchToolchainError",
    "BpatchCompileError",
    "BpatchFormatError",
    "BpatchInjectError",
    "BpatchSymbolError",
]
