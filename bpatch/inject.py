"""
Top-level inject() dispatcher: detect format/arch, parse binary once,
dispatch to inject_elf or inject_pe.
"""

from pathlib import Path

from .errors import BpatchFormatError
from .inject_elf import inject_elf
from .inject_pe import inject_pe
from .log import info


def _detect(binary_path: Path) -> tuple[str, str, object]:
    """
    Parse binary once with LIEF and return (fmt, arch, parsed_binary).
    Raises BpatchFormatError for unsupported formats.
    """
    import lief  # late import so tests can work without it

    try:
        parsed = lief.parse(str(binary_path))
    except Exception as e:
        raise BpatchFormatError(f"Failed to parse {binary_path}: {e}") from e

    if parsed is None:
        raise BpatchFormatError(
            f"LIEF could not parse {binary_path}. "
            "Make sure it is a valid ELF or PE binary."
        )

    if isinstance(parsed, lief.ELF.Binary):
        fmt = "ELF"
        mt  = str(parsed.header.machine_type).upper()
        if "X86_64" in mt or "AMD64" in mt:
            arch = "x86_64"
        elif "AARCH64" in mt or "ARM64" in mt:
            arch = "aarch64"
        else:
            raise BpatchFormatError(
                f"Unsupported ELF architecture: {parsed.header.machine_type}\n"
                "Supported ELF arches: x86_64, aarch64"
            )

    elif isinstance(parsed, lief.PE.Binary):
        fmt = "PE"
        mt  = str(parsed.header.machine).upper()
        if "AMD64" in mt or "X86_64" in mt:
            arch = "x86_64"
        elif "ARM64" in mt or "AARCH64" in mt:
            arch = "aarch64"
        else:
            raise BpatchFormatError(
                f"Unsupported PE architecture: {parsed.header.machine}\n"
                "Supported PE arch: x86_64"
            )

    elif isinstance(parsed, lief.MachO.Binary):
        raise BpatchFormatError("Mach-O is not yet supported.")

    else:
        raise BpatchFormatError(f"Unrecognized binary format: {binary_path}")

    return fmt, arch, parsed


def inject(
    binary_path:      Path,
    target_va:        int,
    payload_c:        Path,
    out:              Path,
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
    """
    Detect format, compile payload, inject trampoline, write output binary.
    Raises BpatchError subclasses on failure — never calls sys.exit().
    """
    fmt, arch, parsed = _detect(binary_path)

    info(f"[*] binary:  {binary_path}")
    info(f"[*] format:  {fmt}")
    info(f"[*] arch:    {arch}")
    info(f"[*] target:  0x{target_va:x}")
    info(f"[*] payload: {payload_c}")
    info(f"[*] output:  {out}")
    if cc_override:     info(f"[*] cc:      {cc_override}")
    if ld_override:     info(f"[*] ld:      {ld_override}")
    if objcopy_override:info(f"[*] objcopy: {objcopy_override}")
    info(f"[*] payload-opt: -{payload_opt}")
    if toolchain_hint != "auto":
        info(f"[*] toolchain preference: {toolchain_hint}")
    if target_override: info(f"[*] target override: {target_override}")
    if payload_cflags:  info(f"[*] payload-cflags:  {' '.join(payload_cflags)}")
    if payload_ldflags: info(f"[*] payload-ldflags: {' '.join(payload_ldflags)}")
    if lto:             info("[*] LTO: on")
    if debug:           info("[*] debug: on")
    if sections:        info("[*] section GC: on")
    if dry_run:         info("[*] DRY RUN — output will not be written")
    print()

    common = dict(
        cc_override=cc_override, ld_override=ld_override,
        objcopy_override=objcopy_override, payload_opt=payload_opt,
        payload_cflags=payload_cflags, payload_ldflags=payload_ldflags,
        toolchain_hint=toolchain_hint, target_override=target_override,
        lto=lto, debug=debug, sections=sections, dry_run=dry_run,
    )

    if fmt == "ELF":
        inject_elf(binary_path, target_va, payload_c, out, arch,
                   parsed_binary=parsed, **common)
    else:
        inject_pe(binary_path, target_va, payload_c, out, arch,
                  parsed_binary=parsed, **common)
