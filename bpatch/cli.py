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
from .inject import inject
from .log import set_quiet, info, ok, warn
from .selftest import self_test, doctor, bootstrap
from .symbols import resolve_symbol_address
from .inject import _detect


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
    ap.add_argument("--at",          metavar="ADDR",
                    help="Injection address in hex incl. imagebase (e.g. 0x140001234)")
    ap.add_argument("--at-symbol",   metavar="NAME",
                    help="Resolve injection address from symbol name via nm")
    ap.add_argument("--payload",     metavar="FILE.c",
                    help="C payload source file (see --list for examples)")
    ap.add_argument("-o", "--output",metavar="OUT",
                    help="Output path (default: <binary>.patched[.exe])")

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
            BPATCH_RT_LINUX_H, BPATCH_RT_WIN64_H, BPATCH_RT_AARCH64_LINUX_H
        )
        if args.pe:
            if args.arch != "x86_64":
                ap.error("--dump-header --pe currently supports only --arch x86_64")
            rt, name = BPATCH_RT_WIN64_H, "bpatch_rt_win64.h"
        else:
            if args.arch == "x86_64":
                rt, name = BPATCH_RT_LINUX_H, "bpatch_rt.h"
            else:
                rt, name = BPATCH_RT_AARCH64_LINUX_H, "bpatch_rt_aarch64.h"
        Path(name).write_text(rt, encoding="utf-8")
        ok(f"[+] Written: {Path(name).resolve()}")
        info(f"    Include in your payload with:  #include \"bpatch_rt.h\"")
        return

    # ---- validate required args for injection ----
    missing = []
    if not args.binary:         missing.append("binary")
    if not args.at and not args.at_symbol:
        missing.append("--at or --at-symbol")
    if args.at and args.at_symbol:
        ap.error("Use either --at or --at-symbol, not both.")
    if not args.payload:        missing.append("--payload")
    if missing:
        ap.print_help()
        print()
        ap.error(f"Missing required arguments: {', '.join(missing)}")

    # ---- resolve paths ----
    binary_path  = Path(args.binary)
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

    if not binary_path.exists():
        ap.error(f"Binary not found: {binary_path}")

    # ---- resolve injection address ----
    if args.at:
        try:
            target_va = int(args.at, 16)
        except ValueError:
            ap.error(f"Invalid address: {args.at!r}  (expected hex, e.g. 0x140001234)")
    else:
        fmt, arch, _ = _detect(binary_path)
        target_va = resolve_symbol_address(
            binary_path, args.at_symbol, fmt, arch,
            cc_override   = args.cc or "",
            toolchain_hint= args.toolchain,
        )

    # ---- resolve output path ----
    if args.output:
        out = Path(args.output)
    else:
        suf = ".exe" if binary_path.suffix.lower() == ".exe" else ""
        out = binary_path.with_suffix(f".patched{suf}")

    if out.resolve() == binary_path.resolve():
        ap.error("Output path is the same as input. Use -o to specify a different path.")

    # ---- inject ----
    inject(
        binary_path, target_va, payload_path, out,
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
    )

    if not args.dry_run:
        ok(f"\n[+] Done. Patched binary: {out}")
        ok(f"    Original is unchanged:  {binary_path}")
    else:
        ok(f"\n[+] Dry run complete. No output written.")
