"""bpatch — static binary injection tool for malware analysis and RE."""

__version__ = "0.3.0"

from .errors import (
    BpatchError,
    BpatchToolchainError,
    BpatchCompileError,
    BpatchFormatError,
    BpatchInjectError,
    BpatchSymbolError,
)
from .inject import inject

__all__ = [
    "__version__",
    "inject",
    "BpatchError",
    "BpatchToolchainError",
    "BpatchCompileError",
    "BpatchFormatError",
    "BpatchInjectError",
    "BpatchSymbolError",
]
