"""
bpatch command-line interface.

Entry point: bpatch.cli:main (also callable as `python -m bpatch`).
All BpatchError subclasses are caught here and converted to exit-code 1.
"""

import argparse
import os
import platform
import sys
from pathlib import Path

from . import __version__
from .errors import BpatchError
from .inject import inject, inject_sites, _detect, _resolve_target_va
from .log import set_quiet, info, ok, warn
from .selftest import self_test, doctor, bootstrap
from .symbols import resolve_symbol_address


# ---------------------------------------------------------------------------
# --list helper
# ---------------------------------------------------------------------------

def _list_examples() -> None:
    here     = Path(__file__).parent.parent   # repo root
    examples = sorted(here.glob("examples/*.c"))
    if not examples:
        warn("No example payloads found in examples/")
        return

    linux = [e for e in examples if not e.stem.endswith("_win")]
    win   = [e for e in examples if e.stem.endswith("_win")]

    ok("Available example payloads:\n")
    if linux:
        ok("  Linux / ELF (x86_64 and aarch64)")
        ok("    x86_64  ARG1=rdi, ARG2=rsi ...")
        ok("    aarch64 ARG1=x0,  ARG2=x1  ...")
        for e in linux:
            lines = e.read_text(encoding="utf-8").splitlines()
            desc  = next(
                (l.lstrip("/* ").rstrip() for l in lines
                 if l.strip().startswith("*") and len(l.strip()) > 2
                 and not l.strip().startswith("**")),
                "",
            )
            ok(f"    {e.name:30s}  {desc}")
    print()
    if win:
        ok("  Windows / PE (MS x64 ABI: ARG1=rcx, ARG2=rdx ...)")
        for e in win:
            lines = e.read_text(encoding="utf-8").splitlines()
            desc  = next(
                (l.lstrip("/* ").rstrip() for l in lines
                 if l.strip().startswith("*") and len(l.strip()) > 2
                 and not l.strip().startswith("**")),
                "",
            )
            ok(f"    {e.name:30s}  {desc}")
    print()


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser(default_toolchain: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="bpatch",
        description="bpatch — static binary injection tool for malware analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Inject at a function entry and dump the first argument (a string)
  bpatch target.exe  --at 0x140001234 --payload dump_string_win.c
  bpatch target.elf  --at 0x401234    --payload dump_string.c
  bpatch target_arm64.elf --at 0x400123 --payload dump_string.c

  # Log all register values every time a site is hit
  bpatch target.exe  --at 0x140001234 --payload log_regs_win.c

  # Force a function to always return 1 (bypass license/anti-debug)
  bpatch target.exe  --at 0x14000ABCD --payload patch_retval_win.c

  # Enable LTO for a smaller payload (recommended with clang + lld)
  bpatch target.elf --at 0x401234 --payload dump_string.c --lto

  # Enable dead-code section GC for an even smaller payload
  bpatch target.elf --at 0x401234 --payload dump_string.c --lto --payload-sections

  # Debug a payload: include symbols, disable optimisation
  bpatch target.elf --at 0x401234 --payload dump_string.c --payload-debug

  # Preview the injection layout without writing output
  bpatch target.elf --at 0x401234 --payload dump_string.c --dry-run

  # Check which toolchains are available
  bpatch --doctor
  bpatch --bootstrap [--yes]
  bpatch --self-test
""",
    )

    # --- positional / core ---
    ap.add_argument("binary",        nargs="?",
                    help="Target binary (.exe or ELF, auto-detected)")

    # Address resolution — mutually exclusive group
    addr_grp = ap.add_mutually_exclusive_group()
    addr_grp.add_argument("--at",          metavar="ADDR",
                    help="Injection address in hex incl. imagebase (e.g. 0x140001234)")
    addr_grp.add_argument("--at-rva",      metavar="RVA",
                    help="Injection RVA (hex) — imagebase is added automatically")
    addr_grp.add_argument("--at-symbol",   metavar="NAME",
                    help="Resolve injection address from debug symbol name via nm")
    addr_grp.add_argument("--at-export",   metavar="NAME",
                    help="Resolve injection address from PE export table (DLL/EXE)")
    addr_grp.add_argument("--at-pattern",  metavar="PATTERN",
                    help='Byte-pattern scan, e.g. "48 8B 05 ?? ?? ?? ??" '
                         "(wildcards: ?? ? * --)")
    ap.add_argument("--at-pattern-nth",    metavar="N", type=int, default=1,
                    help="Which match to use when --at-pattern finds multiple "
                         "results (1-based, default: 1)")

    ap.add_argument("--payload",     metavar="FILE.c",
                    help="C payload source file (see --list for examples)")
    ap.add_argument("-o", "--output",metavar="OUT",
                    help="Output path (default: <binary>.patched[.exe])")

    # Multi-site injection
    ap.add_argument("--sites",        metavar="SITES.json",
                    help="JSON file describing multiple injection sites "
                         "(overrides --at/--payload/--at-* for batch injection)")

    # Undo
    ap.add_argument("--undo",         action="store_true",
                    help="Revert all bpatch injections in binary (uses embedded undo headers)")

    # --- toolchain ---
    ap.add_argument("--cc",          metavar="COMPILER",
                    help="Payload C compiler override (e.g. clang, gcc, "
                         "aarch64-linux-android34-clang)")
    ap.add_argument("--ld",          metavar="LINKER",
                    help="Payload linker override (optional)")
    ap.add_argument("--objcopy",     metavar="OBJCOPY",
                    help="Payload objcopy override (optional)")
    ap.add_argument("--toolchain",   choices=("auto", "gcc", "clang"),
                    default=default_toolchain,
                    help="Preferred compiler family (default: auto, tries clang first)")
    ap.add_argument("--target",      metavar="TRIPLE",
                    help="Override compiler target triple (e.g. x86_64-w64-windows-gnu)")

    # --- payload compile flags ---
    ap.add_argument("--payload-opt", choices=("O0","O1","O2","O3","Os","Oz"),
                    default="O2",
                    help="Payload optimisation level (default: O2)")
    ap.add_argument("--lto",         action="store_true",
                    help="Enable link-time optimisation (-flto). "
                         "Recommended with clang+lld — reduces payload size. "
                         "[MAIN new flag]")
    ap.add_argument("--payload-debug", action="store_true",
                    help="Include debug symbols and force -O0 (for payload development)")
    ap.add_argument("--payload-sections", action="store_true",
                    help="Use -ffunction-sections/-fdata-sections + --gc-sections "
                         "to remove unused code from the payload")
    ap.add_argument("--payload-cflag",  action="append", default=[], metavar="FLAG",
                    help="Extra C compiler flag for payload build (repeatable)")
    ap.add_argument("--payload-ldflag", action="append", default=[], metavar="FLAG",
                    help="Extra linker flag for payload build (repeatable)")

    # --- output control ---
    ap.add_argument("--chain",        action="store_true",
                    help="Allow hooking a site that already starts with a JMP "
                         "(hook chaining — new payload runs before the old one)")
    ap.add_argument("--dry-run",     action="store_true",
                    help="Show injection layout without writing the output binary")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="Suppress [*] informational lines; show only [+]/[!]")

    # --- info modes ---
    ap.add_argument("--dump-header", action="store_true",
                    help="Write bpatch_rt.h to cwd and exit")
    ap.add_argument("--pe",          action="store_true",
                    help="Use PE runtime header with --dump-header")
    ap.add_argument("--arch",        choices=("x86_64", "aarch64"), default="x86_64",
                    help="Architecture for --dump-header (default: x86_64)")
    ap.add_argument("--list",        action="store_true",
                    help="List available example payloads and exit")
    ap.add_argument("--doctor",      action="store_true",
                    help="Check available payload toolchains and exit")
    ap.add_argument("--bootstrap",   action="store_true",
                    help="Install/prepare toolchains (dry-run unless --yes)")
    ap.add_argument("--yes",         action="store_true",
                    help="Execute --bootstrap commands")
    ap.add_argument("--self-test",   action="store_true",
                    help="Build, patch, and run a tiny local validation target")
    ap.add_argument("--version",     action="version",
                    version=f"bpatch {__version__}")

    return ap


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------

def main() -> None:
    # Force UTF-8 output on Windows so box-drawing / arrows render correctly.
    if platform.system() == "Windows":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    default_toolchain = os.environ.get("BPATCH_TOOLCHAIN", "auto").strip().lower()
    if default_toolchain not in ("auto", "gcc", "clang"):
        default_toolchain = "auto"

    ap   = _build_parser(default_toolchain)
    args = ap.parse_args()

    # Apply --quiet globally
    set_quiet(args.quiet)

    try:
        _run(ap, args)
    except BpatchError as exc:
        warn(f"[!] {exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        warn("\n[!] Interrupted.")
        sys.exit(130)


def _run(ap: argparse.ArgumentParser, args) -> None:
    # Mutual-exclusion check for mode flags
    mode_count = sum(bool(x) for x in (
        args.list, args.doctor, args.dump_header,
        args.bootstrap, args.self_test,
    ))
    if mode_count > 1:
        ap.error("Choose only one mode: --list / --doctor / --dump-header / "
                 "--bootstrap / --self-test")

    # --undo is handled early (before injection path)
    if getattr(args, "undo", False):
        if not args.binary:
            ap.error("--undo requires a binary argument")
        binary_path = Path(args.binary)
        if not binary_path.exists():
            ap.error(f"Binary not found: {binary_path}")
        if args.output:
            out = Path(args.output)
        else:
            suf = ".exe" if binary_path.suffix.lower() == ".exe" else ""
            out = binary_path.with_suffix(f".unpatched{suf}")
        if out.resolve() == binary_path.resolve():
            ap.error("Output path is the same as input. Use -o to specify a different path.")
        from .undo import undo_elf, undo_pe
        fmt, arch, _parsed = _detect(binary_path)
        if fmt == "ELF":
            n = undo_elf(binary_path, out, dry_run=args.dry_run)
        else:
            n = undo_pe(binary_path, out, dry_run=args.dry_run)
        if n == 0:
            sys.exit(1)
        return

    # ---- info-only modes ----
    if args.list:
        _list_examples()
        return

    if args.doctor:
        rc = doctor()
        sys.exit(rc)

    if args.bootstrap:
        rc = bootstrap(yes=args.yes)
        sys.exit(rc)

    if args.self_test:
        rc = self_test(
            toolchain_hint  = args.toolchain,
            target_override = args.target or os.environ.get("BPATCH_TARGET", "").strip(),
            cc_override     = args.cc or "",
            ld_override     = args.ld or "",
            objcopy_override= args.objcopy or "",
        )
        sys.exit(rc)

    if args.dump_header:
        from .runtime import (
            BPATCH_RT_LINUX_H, BPATCH_RT_WIN64_H,
            BPATCH_RT_AARCH64_LINUX_H, BPATCH_RT_WIN_ARM64_H,
        )
        if args.pe:
            if args.arch == "x86_64":
                rt, name = BPATCH_RT_WIN64_H,    "bpatch_rt_win64.h"
            else:
                rt, name = BPATCH_RT_WIN_ARM64_H, "bpatch_rt_win_arm64.h"
        else:
            if args.arch == "x86_64":
                rt, name = BPATCH_RT_LINUX_H,         "bpatch_rt.h"
            else:
                rt, name = BPATCH_RT_AARCH64_LINUX_H, "bpatch_rt_aarch64.h"
        Path(name).write_text(rt, encoding="utf-8")
        ok(f"[+] Written: {Path(name).resolve()}")
        info(f"    Include in your payload with:  #include \"bpatch_rt.h\"")
        return

    # ---- validate required args for injection ----
    if not args.binary:
        ap.print_help()
        print()
        ap.error("Missing required argument: binary")

    binary_path = Path(args.binary)
    if not binary_path.exists():
        ap.error(f"Binary not found: {binary_path}")

    # ---- resolve output path ----
    if args.output:
        out = Path(args.output)
    else:
        suf = ".exe" if binary_path.suffix.lower() == ".exe" else ""
        out = binary_path.with_suffix(f".patched{suf}")

    if out.resolve() == binary_path.resolve():
        ap.error("Output path is the same as input. Use -o to specify a different path.")

    common_inject = dict(
        cc_override      = args.cc or "",
        ld_override      = args.ld or "",
        objcopy_override = args.objcopy or "",
        payload_opt      = args.payload_opt,
        payload_cflags   = args.payload_cflag,
        payload_ldflags  = args.payload_ldflag,
        toolchain_hint   = args.toolchain,
        target_override  = args.target or os.environ.get("BPATCH_TARGET", "").strip(),
        lto              = args.lto,
        debug            = args.payload_debug,
        sections         = args.payload_sections,
        dry_run          = args.dry_run,
        chain            = getattr(args, "chain", False),
    )

    # ---- multi-site mode ----
    if getattr(args, "sites", None):
        sites_path = Path(args.sites)
        if not sites_path.exists():
            ap.error(f"--sites file not found: {sites_path}")
        n = inject_sites(binary_path, sites_path, out, **common_inject)
        if not args.dry_run:
            ok(f"\n[+] Done. {n} site(s) patched -> {out}")
            ok(f"    Original is unchanged: {binary_path}")
        else:
            ok(f"\n[+] Dry run complete.")
        return

    # ---- single-site mode ----
    has_addr = any([
        args.at,
        getattr(args, "at_rva", None),
        args.at_symbol,
        getattr(args, "at_export", None),
        getattr(args, "at_pattern", None),
    ])
    if not has_addr:
        ap.print_help()
        print()
        ap.error("Missing injection address: use one of "
                 "--at / --at-rva / --at-symbol / --at-export / --at-pattern")
    if not args.payload:
        ap.print_help()
        print()
        ap.error("Missing required argument: --payload")

    payload_path = Path(args.payload)
    if not payload_path.exists():
        candidate = Path(__file__).parent.parent / "examples" / payload_path.name
        if candidate.exists():
            info(f"[*] Payload not found at {payload_path}, using {candidate}")
            payload_path = candidate
        else:
            ap.error(
                f"Payload not found: {payload_path}\n"
                "Run  bpatch --list  to see available payloads."
            )

    # ---- resolve injection address ----
    fmt, arch, parsed = _detect(binary_path)
    try:
        target_va = _resolve_target_va(
            binary_path,
            at              = args.at,
            at_rva          = getattr(args, "at_rva", None),
            at_symbol       = args.at_symbol,
            at_export       = getattr(args, "at_export", None),
            at_pattern      = getattr(args, "at_pattern", None),
            at_pattern_nth  = getattr(args, "at_pattern_nth", 1),
            fmt             = fmt,
            arch            = arch,
            parsed          = parsed,
            cc_override     = args.cc or "",
            toolchain_hint  = args.toolchain,
        )
    except ValueError as e:
        ap.error(f"Invalid address: {e}")

    # ---- inject ----
    inject(
        binary_path, target_va, payload_path, out,
        **common_inject,
    )

    if not args.dry_run:
        ok(f"\n[+] Done. Patched binary: {out}")
        ok(f"    Original is unchanged:  {binary_path}")
    else:
        ok(f"\n[+] Dry run complete. No output written.")
