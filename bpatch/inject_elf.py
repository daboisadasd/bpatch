"""ELF binary injection via LIEF section addition."""

import os
import platform
import tempfile
from pathlib import Path

from .compiler import compile_payload
from .errors import BpatchInjectError
from .log import info, ok
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


def _write_hook(binary, target_va: int, inject_va: int,
                stolen_sz: int, arch: str) -> None:
    backend = _get_backend(arch)
    full, patch_len, nops = backend.make_entry_patch(target_va, inject_va, stolen_sz)
    info(f"[*] patching 0x{target_va:x}  JMP -> 0x{inject_va:x}  "
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
             "re-patching will chain through previous hook code.")
    return_va = target_va + stolen_sz
    print()

    max_va  = max(s.virtual_address + s.virtual_size for s in binary.segments)
    est_va  = align_up(max_va, 0x1000)
    info(f"[+] estimated .inj vaddr: 0x{est_va:x}")

    prologue, epilogue, content = backend.build_section_content(
        est_va, payload_bytes, payload_off, stolen, return_va, abi="sysv"
    )

    sec         = lief.ELF.Section(inj_name)
    sec.type    = lief.ELF.Section.TYPE.PROGBITS
    sec.flags   = lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.EXECINSTR
    sec.content = list(content)
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
        prologue, epilogue, content = backend.build_section_content(
            real_va, payload_bytes, payload_off, stolen, return_va, abi="sysv"
        )
        for s in binary.sections:
            if s.name == inj_name:
                s.content = list(content)
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
