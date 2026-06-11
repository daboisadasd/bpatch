"""ELF binary injection via LIEF section addition."""

import os
import platform
import tempfile
from pathlib import Path

from .compiler import compile_payload
from .errors import BpatchInjectError
from .log import info, ok, warn
from .undo import build_undo_header, UNDO_HDR_SIZE
from .utils import align_up


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


def _is_patched(raw: bytes, target_va: int, seg_va: int, seg_foff: int) -> bool:
    """Return True if the target site already begins with a JMP/B (already hooked)."""
    off = seg_foff + (target_va - seg_va)
    if off + 5 > len(raw):
        return False
    b = raw[off]
    # x86_64: E9 (near JMP rel32), EB (short JMP rel8), FF 25 (indirect JMP)
    if b in (0xE9, 0xEB):
        return True
    if b == 0xFF and off + 1 < len(raw) and raw[off + 1] == 0x25:
        return True
    # AArch64: B unconditional — top 6 bits = 0b000101
    if off + 4 <= len(raw):
        word = int.from_bytes(raw[off:off + 4], "little")
        if (word >> 26) == 0b000101:
            return True
    return False


def _is_uncond_branch(ins) -> bool:
    return getattr(ins, "mnemonic", "").lower() in ("jmp", "b", "br")


def _print_layout(tgt_va, inj_va, prologue, epilogue, payload,
                  ret_va, inj_label: str = ".inj") -> None:
    ok(f"\n[+] Injection layout:")
    ok(f"    0x{tgt_va:016x}  JMP -> {inj_label}+0x{UNDO_HDR_SIZE:x}  (patch site)")
    ok(f"    0x{inj_va:016x}  [undo header]  ({UNDO_HDR_SIZE} bytes; bpatch --undo to revert)")
    p = inj_va + UNDO_HDR_SIZE
    ok(f"    0x{p:016x}  prologue  ({len(prologue)} bytes)")
    e = p + len(prologue)
    ok(f"    0x{e:016x}  epilogue  ({len(epilogue)} bytes)  <- ret lands here")
    c = e + len(epilogue)
    ok(f"    0x{c:016x}  payload   ({len(payload)} bytes)")
    ok(f"    -> 0x{ret_va:016x}  resume original")


def _write_hook(binary, target_va: int, section_va: int,
                stolen_sz: int, arch: str) -> None:
    """Write the entry JMP/B at target_va -> (section_va + UNDO_HDR_SIZE)."""
    backend = _get_backend(arch)
    code_start = section_va + UNDO_HDR_SIZE
    full, patch_len, nops = backend.make_entry_patch(target_va, code_start, stolen_sz)
    info(f"[*] patching 0x{target_va:x}  JMP -> 0x{code_start:x}  "
         f"({patch_len}B patch + {nops} NOP{'s' if nops != 1 else ''})")
    for i, bv in enumerate(full):
        binary.patch_address(target_va + i, bv)


def inject_elf(
    binary_path:      Path,
    target_va:        int,
    payload_c:        Path,
    out:              Path,
    arch:             str,
    parsed_binary     = None,     # pre-parsed lief.ELF.Binary (optional, saves a parse)
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
    chain:            bool = False,
) -> None:
    import lief  # local import so tests can mock without a global import

    binary = parsed_binary if parsed_binary is not None else lief.parse(str(binary_path))
    raw    = binary_path.read_bytes()
    existing_names = {s.name for s in binary.sections}
    inj_name = _next_inj_name(existing_names, ".inj")

    tgt_seg = next(
        (s for s in binary.segments
         if s.virtual_address <= target_va < s.virtual_address + s.virtual_size),
        None,
    )
    if not tgt_seg:
        raise BpatchInjectError(
            f"0x{target_va:x} not in any ELF load segment. "
            "Check that the address is correct and the binary is not stripped."
        )
    info(f"[+] target segment: va=0x{tgt_seg.virtual_address:x}  "
         f"foff=0x{tgt_seg.file_offset:x}")

    # Detect already-patched sites
    if _is_patched(raw, target_va, tgt_seg.virtual_address, tgt_seg.file_offset):
        if not chain:
            warn(
                f"[!] 0x{target_va:x} already starts with a JMP/B — may already be hooked.\n"
                "    Use --chain to inject anyway (new hook will chain through existing JMP)."
            )
        else:
            info("[*] --chain: target already hooked; chaining new injection.")

    with tempfile.TemporaryDirectory() as tmp:
        payload_bytes, payload_off = compile_payload(
            payload_c, Path(tmp),
            pe=False, arch=arch,
            cc_override=cc_override, ld_override=ld_override,
            objcopy_override=objcopy_override, payload_opt=payload_opt,
            payload_cflags=payload_cflags, payload_ldflags=payload_ldflags,
            toolchain_hint=toolchain_hint, target_override=target_override,
            lto=lto, debug=debug, sections=sections,
        )
    print()

    info("[*] Analyzing injection point...")
    backend = _get_backend(arch)
    stolen, stolen_sz = backend.steal_insns(
        raw, target_va, tgt_seg.virtual_address, tgt_seg.file_offset
    )
    if stolen and _is_uncond_branch(stolen[0]):
        info("[*] Note: target begins with an unconditional branch; "
             "chaining through previous hook code.")
    return_va = target_va + stolen_sz

    # Capture original bytes for undo header BEFORE any patching
    patch_foff    = tgt_seg.file_offset + (target_va - tgt_seg.virtual_address)
    original_bytes = raw[patch_foff: patch_foff + stolen_sz]
    print()

    max_va  = max(s.virtual_address + s.virtual_size for s in binary.segments)
    est_va  = align_up(max_va, 0x1000)
    info(f"[+] estimated .inj vaddr: 0x{est_va:x}")

    # code_start = section_va + UNDO_HDR_SIZE  (prologue begins after the header)
    code_start = est_va + UNDO_HDR_SIZE
    prologue, epilogue, content = backend.build_section_content(
        code_start, payload_bytes, payload_off, stolen, return_va, abi="sysv"
    )

    # Full section: [undo_hdr(32)][prologue][epilogue][payload]
    undo_hdr     = build_undo_header(target_va, original_bytes)
    full_content = undo_hdr + content

    sec         = lief.ELF.Section(inj_name)
    sec.type    = lief.ELF.Section.TYPE.PROGBITS
    sec.flags   = lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.EXECINSTR
    sec.content = list(full_content)
    sec.alignment = 0x10
    binary.add(sec, loaded=True)

    real_va = next(
        (s.virtual_address for s in binary.sections if s.name == inj_name), None
    )
    if real_va is None:
        raise BpatchInjectError(f"{inj_name} not found in binary after add()")
    info(f"[+] LIEF placed {inj_name} at: 0x{real_va:x}")

    if real_va != est_va:
        info(f"[*] Regenerating for actual vaddr 0x{real_va:x}...")
        code_start = real_va + UNDO_HDR_SIZE
        prologue, epilogue, content = backend.build_section_content(
            code_start, payload_bytes, payload_off, stolen, return_va, abi="sysv"
        )
        undo_hdr     = build_undo_header(target_va, original_bytes)
        full_content = undo_hdr + content
        for s in binary.sections:
            if s.name == inj_name:
                s.content = list(full_content)
                break

    _write_hook(binary, target_va, real_va, stolen_sz, arch)

    if dry_run:
        info("[*] --dry-run: skipping output write")
    else:
        binary.write(str(out))
        if platform.system() != "Windows":
            os.chmod(str(out), os.stat(str(out)).st_mode | 0o111)

    _print_layout(target_va, real_va, prologue, epilogue, payload_bytes,
                  return_va, inj_name)
