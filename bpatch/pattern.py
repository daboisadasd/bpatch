"""
Byte-pattern search for finding injection sites without symbols.

Patterns use hex bytes with '??' (or '?') wildcards, e.g.:
    "48 89 5C 24 ?? 48 89 74 24 ??"   — two wildcard bytes
    "E8 ?? ?? ?? ?? 48 85 C0"         — 4-byte wildcard (rel32 call target)

The search is performed only over executable sections/segments so you
don't accidentally match data that happens to look like code.
"""

from __future__ import annotations
import struct
from pathlib import Path
from typing import NamedTuple

from .errors import BpatchFormatError
from .log import info, warn


# ---------------------------------------------------------------------------
# Pattern compilation
# ---------------------------------------------------------------------------

class _CompiledPattern(NamedTuple):
    pattern: bytes
    mask:    bytes   # 0xFF = must match, 0x00 = wildcard
    length:  int


def compile_pattern(pattern_str: str) -> _CompiledPattern:
    """
    Parse a whitespace-separated hex pattern string into (pattern, mask, len).
    Raises ValueError on invalid tokens.

    Accepted wildcard tokens: '??' '?' '*' '--'
    """
    tokens = pattern_str.strip().split()
    if not tokens:
        raise ValueError("Empty pattern string")

    pat = bytearray()
    mask = bytearray()
    for tok in tokens:
        t = tok.strip().upper()
        if t in ("??", "?", "*", "--", "__"):
            pat.append(0x00)
            mask.append(0x00)
        elif len(t) == 2 and all(c in "0123456789ABCDEF" for c in t):
            pat.append(int(t, 16))
            mask.append(0xFF)
        else:
            raise ValueError(
                f"Invalid pattern token {tok!r}. "
                "Use hex bytes (e.g. '48 8B') or '??' for wildcards."
            )
    return _CompiledPattern(bytes(pat), bytes(mask), len(pat))


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _scan_bytes(data: bytes, base_va: int, cp: _CompiledPattern) -> list[int]:
    """Scan *data* for all occurrences of the compiled pattern."""
    n = cp.length
    results: list[int] = []
    if n == 0 or len(data) < n:
        return results
    for i in range(len(data) - n + 1):
        for j in range(n):
            if cp.mask[j] and data[i + j] != cp.pattern[j]:
                break
        else:
            results.append(base_va + i)
    return results


def find_pattern_in_binary(
    binary_path: Path,
    pattern_str: str,
    parsed_binary=None,
) -> list[int]:
    """
    Search all executable sections/segments of *binary_path* for
    *pattern_str*.  Returns a list of matching virtual addresses.

    *parsed_binary* is an optional pre-parsed LIEF object (avoids a
    second parse if the caller already has one).
    """
    try:
        cp = compile_pattern(pattern_str)
    except ValueError as e:
        raise BpatchFormatError(f"Invalid byte pattern: {e}") from e

    import lief  # local import

    parsed = parsed_binary if parsed_binary is not None else lief.parse(
        str(binary_path)
    )
    if parsed is None:
        raise BpatchFormatError(f"LIEF could not parse {binary_path}")

    raw = binary_path.read_bytes()
    matches: list[int] = []

    if isinstance(parsed, lief.ELF.Binary):
        # Scan only LOAD segments with execute permission.
        # LIEF represents p_flags as FLAGS enum; PF_X == 0x1 == FLAGS.X.
        # Use int() cast as a fallback for older LIEF builds that return int flags.
        for seg in parsed.segments:
            try:
                has_x = seg.has(lief.ELF.Segment.FLAGS.X)
            except Exception:
                has_x = bool(int(seg.flags) & 0x1)   # PF_X bit
            if not has_x:
                continue
            foff = seg.file_offset
            fsz  = seg.physical_size
            chunk = raw[foff: foff + fsz]
            matches += _scan_bytes(chunk, seg.virtual_address, cp)

    elif isinstance(parsed, lief.PE.Binary):
        ib = parsed.optional_header.imagebase
        for sec in parsed.sections:
            # Section must have EXECUTE or CODE characteristic
            chars = sec.characteristics
            # IMAGE_SCN_MEM_EXECUTE = 0x20000000  IMAGE_SCN_CNT_CODE = 0x20
            if not (chars & 0x20000020):
                continue
            rptr = sec.offset
            rsz  = sec.size
            chunk = raw[rptr: rptr + rsz]
            matches += _scan_bytes(chunk, ib + sec.virtual_address, cp)

    else:
        raise BpatchFormatError("Pattern search is only supported for ELF and PE binaries.")

    return sorted(set(matches))


def resolve_pattern_address(
    binary_path:    Path,
    pattern_str:    str,
    nth:            int = 1,
    parsed_binary   = None,
) -> int:
    """
    Find the *nth* (1-based) occurrence of *pattern_str* in *binary_path*
    and return its virtual address.
    Raises BpatchFormatError if the pattern is not found or *nth* is out of range.
    """
    hits = find_pattern_in_binary(binary_path, pattern_str, parsed_binary)
    if not hits:
        raise BpatchFormatError(
            f"Pattern not found in any executable section:\n"
            f"  {pattern_str}\n"
            "Check the pattern and make sure the binary is not obfuscated/packed."
        )
    if nth < 1 or nth > len(hits):
        locs = "\n".join(f"  [{i+1}] 0x{a:x}" for i, a in enumerate(hits))
        raise BpatchFormatError(
            f"Pattern has {len(hits)} match(es); --at-pattern-nth {nth} is out of range.\n"
            f"All matches:\n{locs}"
        )
    va = hits[nth - 1]
    info(f"[*] Pattern match [{nth}/{len(hits)}]: 0x{va:x}  "
         f"(pattern: {pattern_str!r})")
    if len(hits) > 1:
        others = [f"0x{a:x}" for a in hits if a != va]
        info(f"[*] Other matches: {', '.join(others[:8])}"
             + (" ..." if len(others) > 8 else ""))
    return va
