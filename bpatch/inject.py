"""
Top-level inject() dispatcher: detect format/arch, parse binary once,
dispatch to inject_elf or inject_pe.

Public API:
  inject()        — single-site injection
  inject_sites()  — multi-site injection from a JSON spec
"""

import json
from pathlib import Path

from .errors import BpatchFormatError, BpatchInjectError
from .inject_elf import inject_elf
from .inject_pe import inject_pe
from .log import info, ok, warn


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


def _resolve_target_va(
    binary_path: Path,
    *,
    at:          str | None  = None,
    at_rva:      str | None  = None,
    at_symbol:   str | None  = None,
    at_export:   str | None  = None,
    at_pattern:  str | None  = None,
    at_pattern_nth: int      = 1,
    fmt:         str         = "",
    arch:        str         = "",
    parsed                   = None,
    cc_override: str         = "",
    toolchain_hint: str      = "auto",
) -> int:
    """
    Resolve exactly one target virtual address from the various --at-* flags.
    Exactly one of the *at* params should be non-None/non-empty.
    """
    if at:
        return int(at, 16)

    if at_rva:
        import lief
        p = parsed if parsed is not None else lief.parse(str(binary_path))
        if isinstance(p, lief.PE.Binary):
            return p.optional_header.imagebase + int(at_rva, 16)
        # ELF: treat RVA as offset from load address of first LOAD segment
        base = min(s.virtual_address for s in p.segments if s.virtual_address)
        return base + int(at_rva, 16)

    if at_symbol:
        from .symbols import resolve_symbol_address
        return resolve_symbol_address(
            binary_path, at_symbol, fmt, arch,
            cc_override=cc_override, toolchain_hint=toolchain_hint,
        )

    if at_export:
        from .symbols import resolve_export_address
        return resolve_export_address(binary_path, at_export, parsed=parsed)

    if at_pattern:
        from .pattern import resolve_pattern_address
        return resolve_pattern_address(
            binary_path, at_pattern, nth=at_pattern_nth, parsed_binary=parsed
        )

    raise BpatchInjectError(
        "No injection address specified. "
        "Use --at, --at-rva, --at-symbol, --at-export, or --at-pattern."
    )


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
    chain:            bool = False,
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
    if chain:           info("[*] chain: on (will hook even if site already patched)")
    if dry_run:         info("[*] DRY RUN — output will not be written")
    print()

    common = dict(
        cc_override=cc_override, ld_override=ld_override,
        objcopy_override=objcopy_override, payload_opt=payload_opt,
        payload_cflags=payload_cflags, payload_ldflags=payload_ldflags,
        toolchain_hint=toolchain_hint, target_override=target_override,
        lto=lto, debug=debug, sections=sections, dry_run=dry_run,
        chain=chain,
    )

    if fmt == "ELF":
        inject_elf(binary_path, target_va, payload_c, out, arch,
                   parsed_binary=parsed, **common)
    else:
        inject_pe(binary_path, target_va, payload_c, out, arch,
                  parsed_binary=parsed, **common)


def inject_sites(
    binary_path: Path,
    sites_json:  Path,
    out:         Path,
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
) -> int:
    """
    Multi-site injection from a JSON spec file.

    JSON format (array of site objects)::

        [
          {
            "at": "0x140001234",          // required (or "at_symbol"/"at_export"/"at_rva"/"at_pattern")
            "payload": "log_regs_win.c",  // required
            "comment": "hook CreateFile"  // optional
          },
          {
            "at_export": "CreateFileW",
            "payload": "hexdump_arg_win.c"
          }
        ]

    Sites are injected sequentially; each round-trip through inject() writes an
    intermediate .patched binary that becomes the input for the next site.
    Returns the number of sites successfully injected.
    """
    spec = json.loads(sites_json.read_text(encoding="utf-8"))
    if not isinstance(spec, list) or not spec:
        raise BpatchInjectError(
            f"--sites JSON must be a non-empty array of site objects: {sites_json}"
        )

    fmt, arch, _parsed = _detect(binary_path)
    ok(f"[+] Multi-site injection: {len(spec)} site(s) from {sites_json.name}")
    ok(f"[+] Format: {fmt}  Arch: {arch}")
    print()

    # Work on a temp copy; final copy goes to out
    import tempfile, shutil
    with tempfile.TemporaryDirectory() as td:
        current = Path(td) / binary_path.name
        shutil.copy2(binary_path, current)

        for i, site in enumerate(spec):
            payload_rel = site.get("payload")
            if not payload_rel:
                raise BpatchInjectError(f"Site {i+1}: missing 'payload' key")

            payload_c = Path(payload_rel)
            if not payload_c.is_absolute() and not payload_c.exists():
                # Try next to sites_json, then in examples/
                cands = [
                    sites_json.parent / payload_c.name,
                    Path(__file__).parent.parent / "examples" / payload_c.name,
                ]
                payload_c = next((c for c in cands if c.exists()), payload_c)

            comment = site.get("comment", "")
            ok(f"[+] Site {i+1}/{len(spec)}: {payload_c.name}"
               + (f"  # {comment}" if comment else ""))

            fmt2, arch2, parsed2 = _detect(current)
            target_va = _resolve_target_va(
                current,
                at           = site.get("at"),
                at_rva       = site.get("at_rva"),
                at_symbol    = site.get("at_symbol"),
                at_export    = site.get("at_export"),
                at_pattern   = site.get("at_pattern"),
                at_pattern_nth = int(site.get("at_pattern_nth", 1)),
                fmt          = fmt2,
                arch         = arch2,
                parsed       = parsed2,
                cc_override  = cc_override,
                toolchain_hint = toolchain_hint,
            )

            step_out = Path(td) / f"{binary_path.stem}_s{i+1}{binary_path.suffix}"
            common = dict(
                cc_override=cc_override, ld_override=ld_override,
                objcopy_override=objcopy_override, payload_opt=payload_opt,
                payload_cflags=payload_cflags, payload_ldflags=payload_ldflags,
                toolchain_hint=toolchain_hint, target_override=target_override,
                lto=lto, debug=debug, sections=sections, dry_run=dry_run,
                chain=chain,
            )

            if fmt2 == "ELF":
                inject_elf(current, target_va, payload_c, step_out, arch2,
                           parsed_binary=parsed2, **common)
            else:
                inject_pe(current, target_va, payload_c, step_out, arch2,
                          parsed_binary=parsed2, **common)

            current = step_out

        if not dry_run:
            shutil.copy2(current, out)
            ok(f"\n[+] All {len(spec)} site(s) injected -> {out}")

    return len(spec)
