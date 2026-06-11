"""
PE binary injection — raw bytearray approach.

We bypass LIEF's PE serializer entirely for the output file.
LIEF 0.17+ binary.write() re-lays out sections and can corrupt bytes in the
original sections.  Strategy:
  1. Use LIEF only for parsing (imagebase, section_alignment).
  2. Work on a bytearray copy of the original raw file.
  3. Patch the JMP directly into raw bytes at the correct file offset.
  4. Manually add a new section header (or extend the tail section as fallback).
  5. Update NumberOfSections and SizeOfImage.
  6. Append .inj content (padded to FileAlignment) at end of file.

PE64 header offsets we care about:
  [0x3C]                      e_lfanew -> offset of "PE\\0\\0"
  [e_lfanew+4]                IMAGE_FILE_HEADER (20 bytes)
    +2  NumberOfSections u16   <- incremented
    +16 SizeOfOptHdr     u16
  [e_lfanew+24]               IMAGE_OPTIONAL_HEADER64
    +56 SizeOfImage      u32   <- updated
    +60 SizeOfHeaders    u32
    +68 FileAlignment    u32   (typically 0x200)
  [e_lfanew+24+SizeOfOptHdr]  section table (40 bytes per entry)
    +0  Name[8], +8 VirtualSize, +12 VirtualAddress,
    +16 SizeOfRawData, +20 PointerToRawData, +36 Characteristics
"""

import struct
import tempfile
from pathlib import Path

from .compiler import compile_payload
from .errors import BpatchInjectError
from .log import info, ok
from .utils import align_up

# Section header field offsets (within the 40-byte entry)
_SEC_NAME    = 0
_SEC_VSIZE   = 8
_SEC_VA      = 12
_SEC_RAWSZ   = 16
_SEC_RAWPTR  = 20
_SEC_CHARS   = 36
_SEC_HDR_SZ  = 40

# Section characteristics: CODE | EXECUTE | READ
_SEC_EXEC = 0x60000020


def _pe_hdr(raw: bytes) -> dict:
    """Parse the PE64 header into a dict of useful offsets and values."""
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    pe_off   = e_lfanew

    # IMAGE_FILE_HEADER
    nsec_off = pe_off + 4 + 2
    nsec     = struct.unpack_from("<H", raw, nsec_off)[0]
    soh_off  = pe_off + 4 + 16 + 2 + 2   # SizeOfOptHdr field
    soh_sz   = struct.unpack_from("<H", raw, pe_off + 4 + 16)[0]

    # IMAGE_OPTIONAL_HEADER64
    opt_off  = pe_off + 24
    soi_off  = opt_off + 56
    fa_off   = opt_off + 60   # SizeOfHeaders in opt header (NOT FileAlignment)
    # FileAlignment is at opt_off + 36 in PE32+
    fa       = struct.unpack_from("<I", raw, opt_off + 36)[0]
    soh      = struct.unpack_from("<I", raw, opt_off + 60)[0]  # SizeOfHeaders

    sectbl   = opt_off + soh_sz

    return {
        "pe_off":   pe_off,
        "nsec_off": nsec_off,
        "nsec":     nsec,
        "soi_off":  soi_off,
        "fa":       fa,
        "soh":      soh,
        "sectbl":   sectbl,
    }


def _pe_sections(raw: bytes, h: dict) -> list[dict]:
    """Parse the PE section table into a list of dicts."""
    secs = []
    for i in range(h["nsec"]):
        base = h["sectbl"] + i * _SEC_HDR_SZ
        name = raw[base: base + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize  = struct.unpack_from("<I", raw, base + _SEC_VSIZE)[0]
        va     = struct.unpack_from("<I", raw, base + _SEC_VA)[0]
        rawsz  = struct.unpack_from("<I", raw, base + _SEC_RAWSZ)[0]
        rawptr = struct.unpack_from("<I", raw, base + _SEC_RAWPTR)[0]
        chars  = struct.unpack_from("<I", raw, base + _SEC_CHARS)[0]
        secs.append(dict(
            name=name, vsize=vsize, va=va,
            rawsz=rawsz, rawptr=rawptr, chars=chars,
            base=base,
        ))
    return secs


def _get_backend(arch: str):
    from bpatch_arch import x86_64 as backend_x86_64
    from bpatch_arch import aarch64 as backend_aarch64
    if arch == "x86_64":
        return backend_x86_64
    if arch == "aarch64":
        return backend_aarch64
    raise BpatchInjectError(f"Unsupported architecture: {arch}")


def _next_inj_name(existing: set[str], base: str = ".inj") -> str:
    if base not in existing:
        return base
    for i in range(1, 0x1000):
        cand = f".i{i:03x}"
        if cand not in existing:
            return cand
    raise BpatchInjectError("Could not allocate a unique injection section name")


def _is_uncond_branch(ins) -> bool:
    return getattr(ins, "mnemonic", "").lower() in ("jmp", "b", "br")


def _print_layout(tgt_va, inj_va, prologue, epilogue, payload,
                  ret_va, inj_label: str = ".inj") -> None:
    ok(f"\n[+] Injection layout:")
    ok(f"    0x{tgt_va:016x}  JMP -> {inj_label}  (patch site)")
    ok(f"    0x{inj_va:016x}  prologue  ({len(prologue)} bytes)")
    e = inj_va + len(prologue)
    ok(f"    0x{e:016x}  epilogue  ({len(epilogue)} bytes)  <- ret lands here")
    p = e + len(epilogue)
    ok(f"    0x{p:016x}  payload   ({len(payload)} bytes)")
    ok(f"    -> 0x{ret_va:016x}  resume original")


def inject_pe(
    binary_path:      Path,
    target_va:        int,
    payload_c:        Path,
    out:              Path,
    arch:             str,
    parsed_binary     = None,     # pre-parsed lief.PE.Binary (optional)
    cc_override:      str  = "",
    ld_override:      str  = "",
    objcopy_override: str  = "",
    payload_opt:      str  = "O2",
    payload_cflags:   list[str] | None = None,
    payload_ldflags:  list[str] | None = None,
    toolchain_hint:   str  = "auto",
    target_override:  str  = "",
    lto:              bool = False,
    debug:            bool = False,
    sections:         bool = False,
    dry_run:          bool = False,
) -> None:
    import lief  # local import

    if arch != "x86_64":
        raise BpatchInjectError(
            f"PE {arch} is not supported yet. Only PE x86_64 is supported."
        )

    parsed    = parsed_binary if parsed_binary is not None else lief.parse(str(binary_path))
    raw       = bytearray(binary_path.read_bytes())
    imagebase = parsed.optional_header.imagebase
    sec_align = parsed.optional_header.section_alignment
    rva       = target_va - imagebase
    info(f"[+] imagebase: 0x{imagebase:x}  target RVA: 0x{rva:x}")

    h    = _pe_hdr(raw)
    secs = _pe_sections(raw, h)
    existing_names = {s["name"] for s in secs}
    inj_name = _next_inj_name(existing_names, ".inj")

    tgt = next(
        (s for s in secs if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsz"])),
        None,
    )
    if tgt is None:
        raise BpatchInjectError(
            f"RVA 0x{rva:x} not in any PE section.\n"
            f"Tip: address should include imagebase 0x{imagebase:x}"
        )

    sec_va   = imagebase + tgt["va"]
    sec_foff = tgt["rawptr"]
    info(f"[+] target section: {tgt['name']!r}  va=0x{sec_va:x}  foff=0x{sec_foff:x}")

    new_hdr_off    = h["sectbl"] + h["nsec"] * _SEC_HDR_SZ
    can_add_section = (new_hdr_off + _SEC_HDR_SZ <= h["soh"])
    if not can_add_section:
        info(f"[*] No room for new section header — falling back to extending tail section.")

    # --- compile payload ---
    with tempfile.TemporaryDirectory() as tmp:
        payload_bytes, payload_off = compile_payload(
            payload_c, Path(tmp),
            pe=True, arch=arch,
            cc_override=cc_override, ld_override=ld_override,
            objcopy_override=objcopy_override, payload_opt=payload_opt,
            payload_cflags=payload_cflags, payload_ldflags=payload_ldflags,
            toolchain_hint=toolchain_hint, target_override=target_override,
            lto=lto, debug=debug, sections=sections,
        )
    print()

    info("[*] Analyzing injection point...")
    backend = _get_backend(arch)
    stolen, stolen_sz = backend.steal_insns(bytes(raw), target_va, sec_va, sec_foff)
    if stolen and _is_uncond_branch(stolen[0]):
        info("[*] Note: target begins with an unconditional branch; "
             "re-patching will chain through previous hook code.")
    return_va = target_va + stolen_sz
    print()

    # --- choose injection placement ---
    host_sec = None
    if can_add_section:
        last_end = max(s["va"] + max(s["vsize"], s["rawsz"]) for s in secs)
        inj_rva    = align_up(last_end, sec_align)
        inj_rawptr = align_up(len(raw), h["fa"])
        inj_va     = imagebase + inj_rva
        info(f"[+] {inj_name} vaddr:   0x{inj_va:x}  (RVA 0x{inj_rva:x})")
        info(f"[+] {inj_name} foffset: 0x{inj_rawptr:x}")
    else:
        host_sec   = max(secs, key=lambda s: s["va"] + max(s["vsize"], s["rawsz"]))
        inj_rawptr = align_up(len(raw), h["fa"])
        inj_off_in_host = inj_rawptr - host_sec["rawptr"]
        if inj_off_in_host < 0:
            raise BpatchInjectError("Internal error: negative host offset for fallback inject")
        inj_rva = host_sec["va"] + inj_off_in_host
        inj_va  = imagebase + inj_rva
        info(f"[+] fallback host section: {host_sec['name']!r}")
        info(f"[+] {inj_name} vaddr:          0x{inj_va:x}  (RVA 0x{inj_rva:x})")
        info(f"[+] {inj_name} foffset:        0x{inj_rawptr:x}")

    prologue, epilogue, content = backend.build_section_content(
        inj_va, payload_bytes, payload_off, stolen, return_va, abi="win64"
    )

    inj_rawsz      = align_up(len(content), h["fa"])
    content_padded = content + b"\x00" * (inj_rawsz - len(content))

    # --- safety: target RVA must have backing raw bytes ---
    patch_foff      = sec_foff + (rva - tgt["va"])
    patch_rva_offset = rva - tgt["va"]
    if patch_rva_offset >= tgt["rawsz"]:
        raise BpatchInjectError(
            f"Target RVA 0x{rva:x} is in the virtual-only tail of section "
            f"{tgt['name']!r} (rawsz=0x{tgt['rawsz']:x}, vsize=0x{tgt['vsize']:x}).\n"
            "This address has no backing bytes on disk and cannot be patched."
        )

    full_patch, patch_len, nops = backend.make_entry_patch(target_va, inj_va, stolen_sz)
    raw[patch_foff: patch_foff + len(full_patch)] = full_patch
    info(f"[*] patching 0x{target_va:x}  JMP -> 0x{inj_va:x}  "
         f"({patch_len}B patch + {nops} NOP{'s' if nops != 1 else ''})")

    if can_add_section:
        name_bytes = inj_name.encode("ascii", errors="strict").ljust(8, b"\x00")
        new_hdr = (
            name_bytes
            + struct.pack("<I", len(content))    # VirtualSize
            + struct.pack("<I", inj_rva)         # VirtualAddress
            + struct.pack("<I", inj_rawsz)       # SizeOfRawData
            + struct.pack("<I", inj_rawptr)      # PointerToRawData
            + struct.pack("<I", 0)               # PointerToRelocations
            + struct.pack("<I", 0)               # PointerToLinenumbers
            + struct.pack("<H", 0)               # NumberOfRelocations
            + struct.pack("<H", 0)               # NumberOfLinenumbers
            + struct.pack("<I", _SEC_EXEC)       # Characteristics
        )
        assert len(new_hdr) == _SEC_HDR_SZ
        raw[new_hdr_off: new_hdr_off + _SEC_HDR_SZ] = new_hdr
        struct.pack_into("<H", raw, h["nsec_off"], h["nsec"] + 1)
    else:
        inj_off_in_host = inj_rawptr - host_sec["rawptr"]
        new_host_rawsz  = max(host_sec["rawsz"], inj_off_in_host + inj_rawsz)
        new_host_vsize  = max(host_sec["vsize"], inj_off_in_host + len(content))
        new_host_chars  = host_sec["chars"] | _SEC_EXEC
        struct.pack_into("<I", raw, host_sec["base"] + _SEC_VSIZE, new_host_vsize)
        struct.pack_into("<I", raw, host_sec["base"] + _SEC_RAWSZ, new_host_rawsz)
        struct.pack_into("<I", raw, host_sec["base"] + _SEC_CHARS, new_host_chars)
        host_sec.update(vsize=new_host_vsize, rawsz=new_host_rawsz, chars=new_host_chars)
        info(f"[*] extended section {host_sec['name']!r}: "
             f"vsize=0x{new_host_vsize:x}, rawsz=0x{new_host_rawsz:x}, "
             f"chars=0x{new_host_chars:08x}")

    if can_add_section:
        new_soi = align_up(inj_rva + inj_rawsz, sec_align)
    else:
        new_soi = align_up(
            max(s["va"] + max(s["vsize"], s["rawsz"]) for s in secs), sec_align
        )
    struct.pack_into("<I", raw, h["soi_off"], new_soi)

    if inj_rawptr > len(raw):
        raw += b"\x00" * (inj_rawptr - len(raw))
    end = inj_rawptr + len(content_padded)
    if end > len(raw):
        raw += b"\x00" * (end - len(raw))
    raw[inj_rawptr:end] = content_padded

    if dry_run:
        info("[*] --dry-run: skipping output write")
    else:
        out.write_bytes(bytes(raw))

    layout_label = inj_name if can_add_section else f"{host_sec['name']}(+inj)"
    _print_layout(target_va, inj_va, prologue, epilogue, payload_bytes,
                  return_va, layout_label)
