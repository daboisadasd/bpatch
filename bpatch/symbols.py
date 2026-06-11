"""Symbol resolution via nm/llvm-nm."""

import re
import subprocess
from pathlib import Path

from .errors import BpatchSymbolError
from .log import info
from .toolchain import find_nm_tool


def parse_nm_symbol_address(nm_stdout: str, symbol: str) -> int | None:
    """
    Parse nm output (both default and --format=posix) and return the symbol's
    virtual address when found.

    Handles:
      default  "0000000140001500 T encrypt_block"
      posix    "encrypt_block T 0000000140001500 000000000000001a"
    C++ demangled names with spaces are handled by matching on the symbol
    token rather than relying on positional parts[-1].
    """
    for raw in nm_stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        # posix format: "name type value size"
        parts = line.split()
        if len(parts) >= 3:
            # Posix: symbol is parts[0], type is parts[1], value is parts[2]
            if parts[0] == symbol and re.fullmatch(r"[0-9A-Fa-f]+", parts[2]):
                return int(parts[2], 16)
            # Default: value is parts[0], type is parts[1], symbol is rest
            name_tok = " ".join(parts[2:])  # handles demangled names with spaces
            if name_tok == symbol and re.fullmatch(r"[0-9A-Fa-f]+", parts[0]):
                return int(parts[0], 16)
    return None


def resolve_symbol_address(
    binary_path:    Path,
    symbol:         str,
    fmt:            str,
    arch:           str,
    cc_override:    str = "",
    toolchain_hint: str = "auto",
) -> int:
    """
    Resolve a symbol name to its virtual address using nm.
    Raises BpatchSymbolError on failure.
    """
    pe     = (fmt == "PE")
    nm_bin = find_nm_tool(pe, arch,
                          cc_override=cc_override,
                          toolchain_hint=toolchain_hint)
    if not nm_bin:
        raise BpatchSymbolError(
            "Could not find nm/llvm-nm to resolve --at-symbol.\n"
            "Provide --at explicitly, or install nm/llvm-nm tools."
        )

    nm = subprocess.run([nm_bin, str(binary_path)], capture_output=True, text=True)
    if nm.returncode != 0:
        raise BpatchSymbolError(
            f"Symbol scan failed with {Path(nm_bin).name}:\n"
            + ((nm.stderr or nm.stdout).strip() or "(no output)")
            + "\nProvide --at explicitly, or use a binary with symbols."
        )

    for cand in (symbol, "_" + symbol):
        va = parse_nm_symbol_address(nm.stdout, cand)
        if va is not None:
            info(f"[*] Resolved symbol {cand!r} -> 0x{va:x} via {Path(nm_bin).name}")
            return va

    raise BpatchSymbolError(
        f"Symbol not found: {symbol!r}\n"
        "The binary may be stripped or the symbol name may differ.\n"
        f"Provide --at explicitly, or check with:  {Path(nm_bin).name} {binary_path}"
    )


# ---------------------------------------------------------------------------
# PE export resolution (via LIEF — no nm needed)
# ---------------------------------------------------------------------------

def resolve_export_address(
    binary_path: Path,
    export_name: str,
    parsed      = None,
) -> int:
    """
    Resolve a PE exported function name to its virtual address.
    Uses LIEF's export table parser — works on stripped binaries as long as
    the export table is intact (common for DLLs).
    Raises BpatchSymbolError if the export is not found.
    """
    import lief
    from .errors import BpatchSymbolError

    p = parsed if parsed is not None else lief.parse(str(binary_path))
    if p is None or not isinstance(p, lief.PE.Binary):
        raise BpatchSymbolError(
            f"--at-export requires a PE binary, but {binary_path} could not be parsed as PE."
        )

    ib = p.optional_header.imagebase
    for exp in p.exported_functions:
        if exp.name == export_name:
            va = ib + exp.address
            info(f"[*] Resolved export {export_name!r} -> 0x{va:x}")
            return va

    # Build a short list of available exports for the error message
    avail = [e.name for e in p.exported_functions]
    sample = ", ".join(repr(n) for n in avail[:10])
    if len(avail) > 10:
        sample += f", ... ({len(avail)} total)"
    raise BpatchSymbolError(
        f"Export {export_name!r} not found in {binary_path.name}.\n"
        f"Available exports: {sample or '(none)'}\n"
        "Use --at-symbol for ELF debug symbols, or --at for a raw address."
    )
