"""
Payload compilation: C source → self-contained flat binary blob.

Key guarantees:
  - No undefined symbols (nm check before linking)
  - No PLT/GOT relocations (readelf check after compile)
  - payload() offset within .text tracked via nm (not assumed to be 0)
  - Payload signature void payload() / void payload(void) rewritten via regex
  - All subprocess failures raise BpatchCompileError (never sys.exit)
  - New flags: --lto, --payload-debug, --payload-sections
"""

import os
import re
import subprocess
from pathlib import Path

from .errors import BpatchCompileError
from .log import info, ok
from .runtime import (
    BPATCH_RT_LINUX_H, BPATCH_RT_WIN64_H,
    BPATCH_RT_AARCH64_LINUX_H, BPATCH_RT_WIN_ARM64_H,
)
from .runtime import _WRAPPER, _LINKER_SCRIPT
from .toolchain import (
    find_toolchain,
    infer_cc_target_flags,
    infer_ld_target_flags,
    infer_tool_prefix_from_cc,
    resolve_near,
)
from .utils import parse_extra_flags

# Arch-specific bad relocation types that indicate external symbol references
_BAD_RELOCS_X86_64  = frozenset({"PLT32", "GOTPCREL", "GOTOFF", "GOT32"})
_BAD_RELOCS_AARCH64 = frozenset({
    "R_AARCH64_ADR_GOT_PAGE",
    "R_AARCH64_LD64_GOT_LO12_NC",
    "R_AARCH64_GOT_LD_PREL19",
    "R_AARCH64_LD64_GOTPAGE_LO15",
})


def _rt_header(pe: bool, arch: str) -> str:
    if pe:
        if arch == "x86_64":
            return BPATCH_RT_WIN64_H
        if arch == "aarch64":
            return BPATCH_RT_WIN_ARM64_H
        raise BpatchCompileError(
            f"PE payload runtime for arch {arch!r} is not supported. "
            "Supported: x86_64, aarch64."
        )
    if arch == "x86_64":
        return BPATCH_RT_LINUX_H
    if arch == "aarch64":
        return BPATCH_RT_AARCH64_LINUX_H
    raise BpatchCompileError(f"ELF payload runtime for arch {arch!r} is not supported.")


def _rewrite_payload_signature(src: str) -> str:
    """
    Inject ctx_t* parameter into the payload() signature and add
    __attribute__((used)) so the compiler and LTO linker cannot
    dead-code-eliminate the function even when it has no callers.
    Tolerates whitespace variations like `void  payload ( void )`.
    """
    pattern = re.compile(
        r'\bvoid\s+payload\s*\(\s*(?:void)?\s*\)',
        re.MULTILINE
    )
    return pattern.sub(
        "__attribute__((used)) void payload(ctx_t *ctx)", src
    )


def _find_bad_relocs(readelf_stdout: str, arch: str) -> list[str]:
    """Return lines with bad (external-symbol) relocations for the given arch."""
    bad_types = _BAD_RELOCS_X86_64 if arch == "x86_64" else _BAD_RELOCS_AARCH64
    return [
        l.strip()
        for l in readelf_stdout.splitlines()
        if any(t in l for t in bad_types)
    ]


def find_payload_offset(nm_bin: str, obj: Path) -> int:
    """
    Use nm to find payload()'s offset within the compiled .text.
    Uses --format=posix for stable, whitespace-safe output.
    Raises BpatchCompileError if payload() is not found.
    """
    nm = subprocess.run(
        [nm_bin, "--format=posix", str(obj)],
        capture_output=True, text=True,
    )
    for line in nm.stdout.splitlines():
        # posix format: "name type value size"
        parts = line.strip().split()
        if len(parts) >= 3 and parts[0] == "payload" and parts[1].upper() in ("T", "t"):
            offset = int(parts[2], 16)
            if offset != 0:
                info(f"[*] payload() is at .text+0x{offset:x} "
                     f"(not offset 0 — helpers emitted first)")
            return offset
    raise BpatchCompileError(
        "Could not find payload() symbol in compiled object.\n"
        "Make sure your payload file defines:  void payload() { ... }"
    )


def compile_payload(
    c_file:           Path,
    tmpdir:           Path,
    pe:               bool  = False,
    arch:             str   = "x86_64",
    cc_override:      str   = "",
    ld_override:      str   = "",
    objcopy_override: str   = "",
    payload_opt:      str   = "O2",
    payload_cflags:   list[str] | None = None,
    payload_ldflags:  list[str] | None = None,
    toolchain_hint:   str   = "auto",
    target_override:  str   = "",
    lto:              bool  = False,
    debug:            bool  = False,
    sections:         bool  = False,
) -> tuple[bytes, int]:
    """
    Compile a C payload file to a self-contained flat binary blob.

    Returns (payload_bytes, payload_entry_offset).

    New flags vs the original bpatch.py:
      lto      — add -flto (link-time optimisation; recommended with clang+lld)
      debug    — add -g and force -O0 (overrides payload_opt)
      sections — add -ffunction-sections/-fdata-sections + --gc-sections
                 to remove dead code from the payload blob

    Main compiler recommendation: clang (tries clang before gcc; handles
    cross-compilation via --target without needing prefixed wrappers).
    """
    rt = _rt_header(pe, arch)
    (tmpdir / "bpatch_rt.h").write_text(rt, encoding="utf-8")
    (tmpdir / "payload.ld").write_text(_LINKER_SCRIPT, encoding="utf-8")

    src = c_file.read_text(encoding="utf-8")
    src = _rewrite_payload_signature(src)
    (tmpdir / "payload.c").write_text(_WRAPPER.format(user_code=src), encoding="utf-8")

    obj    = tmpdir / "payload.o"
    linked = tmpdir / "payload_linked"
    binf   = tmpdir / "payload.bin"

    cc, ld_, oc = find_toolchain(
        pe, arch,
        cc_override=cc_override,
        ld_override=ld_override,
        objcopy_override=objcopy_override,
        toolchain_hint=toolchain_hint,
    )
    cc_target_flags = infer_cc_target_flags(cc, pe, arch, target_override=target_override)
    ld_target_flags = infer_ld_target_flags(ld_, cc, pe, arch)
    env_cflags  = parse_extra_flags(os.environ.get("BPATCH_PAYLOAD_CFLAGS",  ""))
    env_ldflags = parse_extra_flags(os.environ.get("BPATCH_PAYLOAD_LDFLAGS", ""))
    extra_cflags  = env_cflags  + list(payload_cflags  or [])
    extra_ldflags = env_ldflags + list(payload_ldflags or [])

    link_mode = "ld" if ld_ else "cc-driver"
    ld_disp   = ld_ if ld_ else "(compiler driver)"
    info(f"[*] payload toolchain: cc={cc}  ld={ld_disp}  objcopy={oc}  "
         f"link-mode={link_mode}  opt=-{payload_opt}")
    if cc_target_flags:
        info(f"[*] inferred cc target flags: {' '.join(cc_target_flags)}")
    if ld_target_flags:
        info(f"[*] inferred ld target flags: {' '.join(ld_target_flags)}")
    if extra_cflags:
        info(f"[*] extra payload cflags: {' '.join(extra_cflags)}")
    if extra_ldflags:
        info(f"[*] extra payload ldflags: {' '.join(extra_ldflags)}")

    # --- build compile flags ---
    if debug:
        opt_flags = ["-g", "-O0"]
    else:
        opt_flags = ["-" + payload_opt]

    flags = opt_flags + [
        "-fPIC", "-ffreestanding", "-fno-builtin",
        "-fno-stack-protector", "-nostdlib",
    ]
    if arch == "x86_64":
        flags += ["-fcf-protection=none", "-mno-sse", "-mno-sse2"]
        if not pe:
            flags.append("-mno-red-zone")  # Linux SysV ABI only
        if pe:
            # Disable SEH unwind tables (.pdata/.xdata) — they contain ADDR32NB
            # relocations that overflow when the injection section is far from imagebase.
            flags += ["-fno-exceptions", "-fno-unwind-tables",
                      "-fno-asynchronous-unwind-tables"]
    elif arch == "aarch64" and pe:
        # Same reasoning as x86_64 PE: strip .pdata/.xdata unwind entries
        flags += ["-fno-exceptions", "-fno-unwind-tables",
                  "-fno-asynchronous-unwind-tables"]

    if lto:
        flags.append("-flto")
        info("[*] LTO enabled (-flto)")

    if sections:
        flags += ["-ffunction-sections", "-fdata-sections"]
        info("[*] section GC enabled (-ffunction-sections -fdata-sections)")

    # --- compile ---
    cc_cmd = (
        [cc] + cc_target_flags + flags + extra_cflags +
        ["-I", str(tmpdir), "-c", str(tmpdir / "payload.c"), "-o", str(obj)]
    )
    r = subprocess.run(cc_cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise BpatchCompileError(f"Compilation failed:\n{r.stderr}")

    # --- nm: check for undefined symbols ---
    tool_prefix = infer_tool_prefix_from_cc(cc)
    nm_candidates: list[str] = []
    if tool_prefix:
        nm_candidates += [tool_prefix + "nm", tool_prefix + "llvm-nm"]
    nm_candidates += ["llvm-nm", "nm"]
    nm_bin = resolve_near(cc, tuple(nm_candidates))
    if not nm_bin:
        raise BpatchCompileError(
            "Could not find nm/llvm-nm for payload symbol lookup."
        )

    nm = subprocess.run([nm_bin, "--format=posix", str(obj)],
                        capture_output=True, text=True)
    undef = [
        l.strip() for l in nm.stdout.splitlines()
        if len(l.split()) >= 2 and l.split()[1].upper() == "U"
    ]
    if undef:
        raise BpatchCompileError(
            "Undefined references in payload (will crash at runtime):\n"
            + "\n".join(f"  {u}" for u in undef)
        )

    # --- readelf/objdump: check for PLT/GOT relocations ---
    re_candidates: list[str] = []
    if tool_prefix:
        re_candidates += [
            tool_prefix + "readelf", tool_prefix + "llvm-readelf",
            tool_prefix + "objdump", tool_prefix + "llvm-objdump",
        ]
    re_candidates += ["llvm-readelf", "readelf", "llvm-objdump", "objdump"]
    re_bin = resolve_near(cc, tuple(re_candidates))
    if not re_bin:
        raise BpatchCompileError(
            "Could not find readelf/objdump for relocation check."
        )
    relf = subprocess.run([re_bin, "-r", str(obj)], capture_output=True, text=True)
    bad = _find_bad_relocs(relf.stdout, arch)
    if bad:
        raise BpatchCompileError(
            "Bad relocations (PLT/GOT) — payload references external symbols:\n"
            + "\n".join(f"  {b}" for b in bad)
        )

    # --- link ---
    link_ldflags = list(ld_target_flags) + list(extra_ldflags)
    if lto and ld_:
        # lld supports --lto-O2; GNU ld needs gold plugin — warn on mismatch
        from pathlib import Path as _P
        ld_name = _P(ld_).name.lower()
        if "lld" in ld_name:
            link_ldflags.append("--lto-O2")
            # --undefined=payload prevents lld's LTO from dead-code-eliminating
            # the payload() function (it has no callers in the bitcode).
            link_ldflags += ["--undefined=payload"]
        # else: -flto in object will trigger gold LTO if plugin is available

    if sections:
        link_ldflags.append("--gc-sections")

    if ld_:
        ld_cmd = (
            [ld_] + link_ldflags +
            ["-T", str(tmpdir / "payload.ld"), "-o", str(linked), str(obj)]
        )
        r = subprocess.run(ld_cmd, capture_output=True, text=True)
    else:
        # Compiler-driver fallback
        driver_ldflags = [f"-Wl,-T,{tmpdir / 'payload.ld'}"]
        for f in link_ldflags:
            driver_ldflags.append(f if f.startswith("-Wl,") else f"-Wl,{f}")
        if lto:
            driver_ldflags.append("-flto")
        cc_link_cmd = (
            [cc] + cc_target_flags + ["-nostdlib"] + driver_ldflags +
            [str(obj), "-o", str(linked)]
        )
        r = subprocess.run(cc_link_cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise BpatchCompileError(f"Link failed:\n{r.stderr}")

    subprocess.run(
        [oc, "-O", "binary", str(linked), str(binf)], check=True
    )
    data = binf.read_bytes().rstrip(b"\x00") + b"\x00"

    # Decide which binary to run nm on:
    #  - LTO + ELF linker: nm on the linked output (bitcode .o gives "--------")
    #  - PE build:         nm on the .o (linked output is PE COFF — nm gives wrong VAs)
    #  - Non-LTO:          nm on the .o is always correct
    nm_target = linked if (lto and not pe) else obj
    payload_offset = find_payload_offset(nm_bin, nm_target)
    ok(f"[+] payload compiled: {len(data)} bytes  "
       f"(text+rodata flat binary, payload() at +0x{payload_offset:x})")
    return data, payload_offset
