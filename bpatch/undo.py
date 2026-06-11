"""
Undo header embedded at the start of every injected section.

Layout (UNDO_HDR_SIZE = 32 bytes):
  offset  0  magic[4]         = b"BPAT"
  offset  4  version (u8)     = 1
  offset  5  flags   (u8)     = 0 (reserved)
  offset  6  stolen_count(u8) = bytes overwritten at patch site (max 16)
  offset  7  pad     (u8)     = 0
  offset  8  patch_va (u64)   = virtual address that was patched
  offset 16  stolen_bytes[16] = original bytes at that address

The code section therefore starts at inj_va + UNDO_HDR_SIZE, so the
JMP/B trampoline must target (inj_va + UNDO_HDR_SIZE).

To revert an injection:
  1. Find all .inj* sections; read the undo header.
  2. Restore stolen_bytes at patch_va in the raw binary.
  3. Clear the section (PE: zero header entry; ELF: remove section).
"""

from __future__ import annotations
import struct
from pathlib import Path

from .errors import BpatchInjectError
from .log import info, ok, warn

UNDO_MAGIC     = b"BPAT"
UNDO_VERSION   = 1
UNDO_HDR_SIZE  = 32   # total header bytes; must be multiple of instruction size


def build_undo_header(patch_va: int, stolen_bytes: bytes) -> bytes:
    """
    Build a 32-byte undo header to prepend to the injected section content.
    *stolen_bytes* are the ORIGINAL bytes at *patch_va* (before any patching).
    """
    count = len(stolen_bytes)
    if count > 16:
        raise BpatchInjectError(
            f"Too many stolen bytes for undo header: {count} > 16"
        )
    hdr = bytearray(UNDO_HDR_SIZE)
    hdr[0:4] = UNDO_MAGIC
    hdr[4]   = UNDO_VERSION
    hdr[5]   = 0          # flags
    hdr[6]   = count
    hdr[7]   = 0          # pad
    struct.pack_into("<Q", hdr, 8, patch_va)
    hdr[16:16 + count] = stolen_bytes
    return bytes(hdr)


def _parse_undo_header(data: bytes, offset: int = 0) -> dict | None:
    """
    Try to parse an undo header at *offset* in *data*.
    Returns a dict with keys: version, flags, stolen_count, patch_va, stolen_bytes
    or None if the magic is absent.
    """
    if len(data) < offset + UNDO_HDR_SIZE:
        return None
    if data[offset:offset + 4] != UNDO_MAGIC:
        return None
    version      = data[offset + 4]
    flags        = data[offset + 5]
    stolen_count = data[offset + 6]
    patch_va,    = struct.unpack_from("<Q", data, offset + 8)
    stolen_bytes = bytes(data[offset + 16: offset + 16 + stolen_count])
    return dict(
        version=version, flags=flags,
        stolen_count=stolen_count,
        patch_va=patch_va,
        stolen_bytes=stolen_bytes,
    )


# ---------------------------------------------------------------------------
# ELF undo
# ---------------------------------------------------------------------------

def undo_elf(binary_path: Path, out: Path, dry_run: bool = False) -> int:
    """
    Revert all bpatch injections from an ELF binary.
    Returns number of sites reverted.
    """
    import lief
    import os, platform

    binary = lief.parse(str(binary_path))
    if binary is None or not isinstance(binary, lief.ELF.Binary):
        raise BpatchInjectError(f"Not a valid ELF binary: {binary_path}")

    raw = bytearray(binary_path.read_bytes())
    reverted = 0

    for sec in list(binary.sections):
        if not (sec.name.startswith(".inj") or sec.name.startswith(".i0")
                or sec.name.startswith(".i1") or sec.name.startswith(".i2")):
            # quick filter — also accept .inj, .i001 ... .ifff
            if not (sec.name == ".inj" or
                    (len(sec.name) == 5 and sec.name.startswith(".i") and
                     all(c in "0123456789abcdef" for c in sec.name[2:]))):
                continue

        sec_data = bytes(sec.content)
        hdr = _parse_undo_header(sec_data)
        if hdr is None:
            warn(f"[!] Section {sec.name!r} has no bpatch undo header — skipping")
            continue

        patch_va     = hdr["patch_va"]
        stolen_bytes = hdr["stolen_bytes"]
        ok(f"[+] Reverting {sec.name!r}: restoring {len(stolen_bytes)} bytes "
           f"at 0x{patch_va:x}")

        # Find the raw file offset for patch_va
        seg = next(
            (s for s in binary.segments
             if s.virtual_address <= patch_va < s.virtual_address + s.virtual_size),
            None
        )
        if seg is None:
            warn(f"[!] Could not locate segment for 0x{patch_va:x} — skipping")
            continue
        foff = seg.file_offset + (patch_va - seg.virtual_address)
        raw[foff: foff + len(stolen_bytes)] = stolen_bytes
        reverted += 1

    if reverted == 0:
        warn("[!] No bpatch injections found to undo.")
        return 0

    if dry_run:
        info("[*] --dry-run: would revert {reverted} injection(s), not writing")
    else:
        out.write_bytes(bytes(raw))
        if platform.system() != "Windows":
            os.chmod(str(out), os.stat(str(out)).st_mode | 0o111)
        ok(f"[+] Reverted {reverted} injection(s) -> {out}")

    return reverted


# ---------------------------------------------------------------------------
# PE undo
# ---------------------------------------------------------------------------

def undo_pe(binary_path: Path, out: Path, dry_run: bool = False) -> int:
    """
    Revert all bpatch injections from a PE binary.
    Returns number of sites reverted.
    """
    import struct as _s

    from .inject_pe import _pe_hdr, _pe_sections, _SEC_HDR_SZ

    raw = bytearray(binary_path.read_bytes())
    h = _pe_hdr(raw)
    secs = _pe_sections(raw, h)

    import lief
    parsed = lief.parse(str(binary_path))
    imagebase = parsed.optional_header.imagebase
    reverted = 0

    for sec in secs:
        name = sec["name"]
        if not (name == ".inj" or
                (len(name) == 5 and name.startswith(".i") and
                 all(c in "0123456789abcdef" for c in name[2:]))):
            continue

        rptr = sec["rawptr"]
        rsz  = sec["rawsz"]
        if rptr == 0 or rsz < UNDO_HDR_SIZE:
            continue

        sec_data = bytes(raw[rptr: rptr + rsz])
        hdr = _parse_undo_header(sec_data)
        if hdr is None:
            warn(f"[!] Section {name!r} has no bpatch undo header — skipping")
            continue

        patch_va     = hdr["patch_va"]
        stolen_bytes = hdr["stolen_bytes"]
        ok(f"[+] Reverting {name!r}: restoring {len(stolen_bytes)} bytes "
           f"at 0x{patch_va:x}")

        # Find file offset for patch_va (search all sections)
        rva = patch_va - imagebase
        host = next(
            (s for s in secs
             if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsz"])),
            None
        )
        if host is None:
            warn(f"[!] Could not locate section for RVA 0x{rva:x} — skipping")
            continue
        foff = host["rawptr"] + (rva - host["va"])
        raw[foff: foff + len(stolen_bytes)] = stolen_bytes

        # Zero the .inj section header entry (mark as removed)
        _s.pack_into("8s", raw, sec["base"], b"\x00" * 8)  # zero name
        _s.pack_into("<I", raw, sec["base"] + 8,  0)       # VirtualSize = 0
        _s.pack_into("<I", raw, sec["base"] + 12, 0)       # VirtualAddress = 0
        # Decrement section count
        nsec = _s.unpack_from("<H", raw, h["nsec_off"])[0]
        _s.pack_into("<H", raw, h["nsec_off"], max(0, nsec - 1))
        reverted += 1

    if reverted == 0:
        warn("[!] No bpatch injections found to undo.")
        return 0

    if dry_run:
        info(f"[*] --dry-run: would revert {reverted} injection(s), not writing")
    else:
        out.write_bytes(bytes(raw))
        ok(f"[+] Reverted {reverted} injection(s) -> {out}")

    return reverted
