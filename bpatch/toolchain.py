"""
Toolchain discovery: locate cc, ld, and objcopy for payload compilation.

Priority order:
  1. CLI overrides  (--cc / --ld / --objcopy)
  2. Scoped env     BPATCH_<ELF|PE>_<ARCH>_{CC,LD,OBJCOPY}
  3. Global env     BPATCH_{CC,LD,OBJCOPY}
  4. Auto-discovery (clang preferred, gcc fallback)

Clang is tried first in auto-discovery because it handles cross-compilation
cleanly via --target flags without needing a separate wrapper executable.
"""

import os
import platform
import re
from pathlib import Path

from .errors import BpatchToolchainError
from .utils import resolve_exe, resolve_near, dedupe_keep_order

# ---------------------------------------------------------------------------
# Version ranges — extend these when new compiler versions ship
# ---------------------------------------------------------------------------
_CLANG_VERSIONS = list(range(22, 14, -1))   # 22 down to 15
_GCC_VERSIONS   = list(range(16, 11, -1))   # 16 down to 12

# Canonical tool-set tuples: (cc, ld_candidates, objcopy_candidates)
_LD_LLD   = ("ld.lld", "lld", "ld", "ld.bfd")
_LD_BFD   = ("ld", "ld.bfd", "ld.gold", "ld.lld", "lld")
_OC_LLVM  = ("llvm-objcopy", "objcopy")
_OC_GNU   = ("objcopy", "llvm-objcopy")


def _clang_row(name: str) -> tuple:
    return (name, _LD_LLD, _OC_LLVM)


def _gcc_row(name: str) -> tuple:
    return (name, _LD_BFD, _OC_GNU)


# ---------------------------------------------------------------------------
# NDK detection
# ---------------------------------------------------------------------------

def _extract_android_api_from_name(name: str) -> int:
    m = re.search(r"aarch64-linux-android(\d+)-clang", name)
    return int(m.group(1)) if m else -1


def find_ndk_aarch64_toolchain() -> tuple[str, str, str] | None:
    """
    Locate an Android NDK aarch64 toolchain:
      aarch64-linux-android<api>-clang + ld.lld + llvm-objcopy
    Returns (cc, ld, objcopy) or None.
    """
    host_tag = {
        "Windows": "windows-x86_64",
        "Linux":   "linux-x86_64",
        "Darwin":  "darwin-x86_64",
    }.get(platform.system(), "")

    ndk_roots: list[Path] = []
    for env_name in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_HOME"):
        v = os.environ.get(env_name, "").strip()
        if v:
            p = Path(v)
            if p.exists():
                ndk_roots.append(p)

    seen: set[str] = set()
    uniq_roots: list[Path] = []
    for r in ndk_roots:
        k = str(r.resolve())
        if k not in seen:
            seen.add(k)
            uniq_roots.append(r)

    if host_tag:
        for root in uniq_roots:
            bin_dir = root / "toolchains" / "llvm" / "prebuilt" / host_tag / "bin"
            if not bin_dir.is_dir():
                continue
            wrappers: list[Path] = []
            for p in bin_dir.glob("aarch64-linux-android*-clang*"):
                if "clang++" not in p.name.lower() and p.is_file():
                    wrappers.append(p)
            wrappers.sort(key=lambda p: _extract_android_api_from_name(p.name))
            for cc_path in reversed(wrappers):
                cc = str(cc_path)
                ld_ = resolve_near(cc, ("ld.lld", "lld"))
                oc  = resolve_near(cc, ("llvm-objcopy", "objcopy"))
                if ld_ and oc:
                    return cc, ld_, oc

    # PATH fallback — highest API first
    for api in (35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21):
        cc = resolve_exe(f"aarch64-linux-android{api}-clang")
        if not cc:
            continue
        ld_ = resolve_near(cc, ("ld.lld", "lld"))
        oc  = resolve_near(cc, ("llvm-objcopy", "objcopy"))
        if ld_ and oc:
            return cc, ld_, oc

    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def prefer_by_cc(cc: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return (ld_candidates, objcopy_candidates) matched to the compiler flavor."""
    cc_name = Path(cc).name.lower()
    if "clang" in cc_name:
        return _LD_LLD, _OC_LLVM
    return _LD_BFD, _OC_GNU


def ordered_candidates(
    candidates: list[tuple],
    toolchain_hint: str,
) -> list[tuple]:
    """Re-order *candidates* so the hinted compiler family comes first."""
    if toolchain_hint == "auto":
        return candidates
    preferred, other = [], []
    for cand in candidates:
        name = cand[0].lower()
        is_gcc   = ("gcc" in name) or (name == "cc")
        is_clang = "clang" in name
        if   toolchain_hint == "gcc"   and is_gcc:   preferred.append(cand)
        elif toolchain_hint == "clang" and is_clang: preferred.append(cand)
        else:                                         other.append(cand)
    return preferred + other


def infer_tool_prefix_from_cc(cc: str) -> str:
    """
    Derive the tool prefix from a cross-compiler name.
    E.g.  x86_64-w64-mingw32-gcc  →  x86_64-w64-mingw32-
    """
    base = Path(cc).name
    base = re.sub(r"\.(exe|cmd|bat)$", "", base, flags=re.IGNORECASE)
    m = re.match(r"(.+-)(gcc|clang)(-\d+)?$", base, flags=re.IGNORECASE)
    return m.group(1) if m else ""


def infer_cc_target_flags(cc: str, pe: bool, arch: str,
                          target_override: str = "") -> list[str]:
    """
    For a plain (non-cross) clang, infer --target so the payload matches the
    destination binary's ABI.  Cross-wrapper clang names already encode the target.
    """
    if target_override:
        return [f"--target={target_override}"]
    cc_name = Path(cc).name.lower()
    if "clang" not in cc_name:
        return []
    # Cross-wrapper already bakes target into the executable name.
    if re.match(r".+-.+-clang(-\d+)?(\.exe)?$", cc_name):
        return []
    if pe and arch == "x86_64":
        return ["--target=x86_64-w64-windows-gnu"]
    if (not pe) and arch == "aarch64":
        return ["--target=aarch64-linux-gnu"]
    return []


def infer_ld_target_flags(ld: str, cc: str, pe: bool, arch: str) -> list[str]:
    """Add -m i386pep for PE/x86_64 when the linker isn't a MinGW-prefixed one."""
    if not pe or arch != "x86_64":
        return []
    ld_name   = Path(ld).name.lower()
    cc_prefix = infer_tool_prefix_from_cc(cc).lower()
    if "x86_64-w64-mingw32-" in cc_prefix or "mingw" in ld_name:
        return []
    if ld_name in ("ld", "ld.lld", "lld", "ld.exe", "ld.lld.exe", "lld.exe"):
        return ["-m", "i386pep"]
    return []


def _toolchain_from_candidate(
    cc_candidate: str,
    ld_candidates: tuple[str, ...],
    objcopy_candidates: tuple[str, ...],
    allow_missing_ld: bool = False,
) -> tuple[str, str, str] | None:
    cc = resolve_exe(cc_candidate)
    if not cc:
        return None
    ld_ = resolve_near(cc, ld_candidates)
    oc  = resolve_near(cc, objcopy_candidates)
    if not oc:
        return None
    if not ld_ and not allow_missing_ld:
        return None
    return cc, ld_, oc


def env_toolchain_overrides(pe: bool, arch: str) -> tuple[str, str, str]:
    """
    Read BPATCH_* env vars in priority order:
      scoped   BPATCH_<ELF|PE>_<ARCH>_{CC,LD,OBJCOPY}
      legacy   BPATCH_AARCH64_{CC,LD,OBJCOPY}  (aarch64 ELF only)
      global   BPATCH_{CC,LD,OBJCOPY}
    """
    scope = f"{'PE' if pe else 'ELF'}_{arch.upper().replace('-', '_')}"
    scope_cc = os.environ.get(f"BPATCH_{scope}_CC",      "").strip()
    scope_ld = os.environ.get(f"BPATCH_{scope}_LD",      "").strip()
    scope_oc = os.environ.get(f"BPATCH_{scope}_OBJCOPY", "").strip()

    legacy_cc = legacy_ld = legacy_oc = ""
    if (not pe) and arch == "aarch64":
        legacy_cc = os.environ.get("BPATCH_AARCH64_CC",      "").strip()
        legacy_ld = os.environ.get("BPATCH_AARCH64_LD",      "").strip()
        legacy_oc = os.environ.get("BPATCH_AARCH64_OBJCOPY", "").strip()

    global_cc = os.environ.get("BPATCH_CC",      "").strip()
    global_ld = os.environ.get("BPATCH_LD",      "").strip()
    global_oc = os.environ.get("BPATCH_OBJCOPY", "").strip()

    return (
        scope_cc or legacy_cc or global_cc,
        scope_ld or legacy_ld or global_ld,
        scope_oc or legacy_oc or global_oc,
    )


# ---------------------------------------------------------------------------
# Main auto-discovery
# ---------------------------------------------------------------------------

def auto_toolchain(pe: bool, arch: str,
                   toolchain_hint: str = "auto") -> tuple[str, str, str]:
    """
    Return (cc, ld, objcopy) for the requested format/arch.
    Clang is tried before GCC in auto mode.
    Raises BpatchToolchainError when no toolchain is found.
    """
    if not pe:
        if arch == "x86_64":
            candidates = (
                # --- clang family (preferred) ---
                [_clang_row("clang")]
                + [_clang_row(f"clang-{v}") for v in _CLANG_VERSIONS]
                # cross-prefixed clang
                + [("x86_64-linux-gnu-clang",          _LD_LLD, _OC_LLVM),
                   ("x86_64-unknown-linux-gnu-clang",  _LD_LLD, _OC_LLVM),
                   ("x86_64-pc-linux-gnu-clang",       _LD_LLD, _OC_LLVM)]
                # --- gcc family (fallback) ---
                + [_gcc_row("gcc")]
                + [_gcc_row(f"gcc-{v}") for v in _GCC_VERSIONS]
                + [("x86_64-linux-gnu-gcc",
                    ("x86_64-linux-gnu-ld", "ld", "ld.bfd"),
                    ("x86_64-linux-gnu-objcopy", "objcopy", "llvm-objcopy")),
                   ("x86_64-unknown-linux-gnu-gcc",
                    ("x86_64-unknown-linux-gnu-ld", "ld", "ld.bfd"),
                    ("x86_64-unknown-linux-gnu-objcopy", "objcopy", "llvm-objcopy")),
                   ("x86_64-pc-linux-gnu-gcc",
                    ("x86_64-pc-linux-gnu-ld", "ld", "ld.bfd"),
                    ("x86_64-pc-linux-gnu-objcopy", "objcopy", "llvm-objcopy")),
                   _gcc_row("cc")]
            )
            for cc_c, ld_c, oc_c in ordered_candidates(candidates, toolchain_hint):
                tc = _toolchain_from_candidate(cc_c, ld_c, oc_c, allow_missing_ld=True)
                if tc:
                    return tc
            raise BpatchToolchainError(
                "Could not find an x86_64 ELF toolchain.\n"
                "Tried clang/gcc families. Install clang or gcc + binutils, then retry."
            )

        if arch == "aarch64":
            pfx = os.environ.get("BPATCH_AARCH64_PREFIX", "").strip()
            prefixes = [pfx] if pfx else []
            prefixes += [
                "aarch64-linux-gnu-",
                "aarch64-none-linux-gnu-",
                "aarch64-unknown-linux-gnu-",
                "aarch64-unknown-linux-musl-",
                "aarch64-linux-musl-",
                "aarch64-linux-android-",
            ]
            cc_order = ("clang", "gcc") if toolchain_hint == "clang" else ("clang", "gcc")
            for prefix in prefixes:
                for cc_name in cc_order:
                    cc = resolve_exe(prefix + cc_name)
                    if not cc:
                        continue
                    ld_names, oc_names = prefer_by_cc(cc)
                    ld_ = resolve_near(cc, (prefix + "ld",) + ld_names)
                    oc  = resolve_near(cc, (prefix + "objcopy",) + oc_names)
                    if ld_ and oc:
                        return cc, ld_, oc

            ndk_tc = find_ndk_aarch64_toolchain()
            if ndk_tc:
                return ndk_tc

            # Last resort: plain clang + lld + llvm-objcopy
            tc = _toolchain_from_candidate("clang", _LD_LLD, _OC_LLVM, allow_missing_ld=True)
            if tc:
                return tc

            raise BpatchToolchainError(
                "Could not find an AArch64 ELF toolchain.\n"
                "Tried prefixed clang/gcc (aarch64-linux-gnu-*, aarch64-linux-android-*)\n"
                "and Android NDK wrappers.\n"
                "Set BPATCH_AARCH64_PREFIX or BPATCH_ELF_AARCH64_CC, or install:\n"
                "  apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu\n"
                "  # or: clang + lld + llvm-objcopy with aarch64-linux-gnu target"
            )

        raise BpatchToolchainError(f"Unsupported ELF architecture: {arch}")

    # --- PE (x86_64 only for now) ---
    if arch != "x86_64":
        raise BpatchToolchainError(
            f"PE {arch} is not supported yet. Only PE x86_64 is supported."
        )

    if platform.system() == "Windows":
        candidates = (
            [("x86_64-w64-mingw32-clang",
              ("x86_64-w64-mingw32-ld", "ld.lld", "lld", "ld"),
              ("x86_64-w64-mingw32-objcopy", "llvm-objcopy", "objcopy")),
             ("x86_64-unknown-w64-mingw32-clang",
              ("x86_64-unknown-w64-mingw32-ld", "ld.lld", "lld", "ld"),
              ("x86_64-unknown-w64-mingw32-objcopy", "llvm-objcopy", "objcopy"))]
            + [_clang_row(f"clang-{v}") for v in _CLANG_VERSIONS]
            + [_clang_row("clang")]
            + [("x86_64-w64-mingw32-gcc",
                ("x86_64-w64-mingw32-ld", "ld", "ld.bfd", "ld.lld", "lld"),
                ("x86_64-w64-mingw32-objcopy", "objcopy", "llvm-objcopy")),
               ("x86_64-unknown-w64-mingw32-gcc",
                ("x86_64-unknown-w64-mingw32-ld", "ld", "ld.bfd", "ld.lld", "lld"),
                ("x86_64-unknown-w64-mingw32-objcopy", "objcopy", "llvm-objcopy"))]
            + [_gcc_row(f"gcc-{v}") for v in _GCC_VERSIONS]
            + [_gcc_row("gcc")]
        )
    else:
        candidates = (
            [("x86_64-w64-mingw32-clang",
              ("x86_64-w64-mingw32-ld", "ld.lld", "lld", "ld"),
              ("x86_64-w64-mingw32-objcopy", "llvm-objcopy", "objcopy")),
             ("x86_64-unknown-w64-mingw32-clang",
              ("x86_64-unknown-w64-mingw32-ld", "ld.lld", "lld", "ld"),
              ("x86_64-unknown-w64-mingw32-objcopy", "llvm-objcopy", "objcopy"))]
            + [("clang-" + str(v),
                ("ld.lld", "lld", "x86_64-w64-mingw32-ld", "ld"),
                ("llvm-objcopy", "x86_64-w64-mingw32-objcopy", "objcopy"))
               for v in _CLANG_VERSIONS]
            + [("clang",
                ("ld.lld", "lld", "x86_64-w64-mingw32-ld", "ld"),
                ("llvm-objcopy", "x86_64-w64-mingw32-objcopy", "objcopy")),
               ("x86_64-w64-mingw32-gcc",
                ("x86_64-w64-mingw32-ld", "ld", "ld.bfd", "ld.lld", "lld"),
                ("x86_64-w64-mingw32-objcopy", "objcopy", "llvm-objcopy")),
               ("x86_64-unknown-w64-mingw32-gcc",
                ("x86_64-unknown-w64-mingw32-ld", "ld", "ld.bfd", "ld.lld", "lld"),
                ("x86_64-unknown-w64-mingw32-objcopy", "objcopy", "llvm-objcopy"))]
            + [_gcc_row(f"gcc-{v}") for v in _GCC_VERSIONS]
            + [_gcc_row("gcc")]
        )

    for cc_c, ld_c, oc_c in ordered_candidates(candidates, toolchain_hint):
        tc = _toolchain_from_candidate(cc_c, ld_c, oc_c, allow_missing_ld=True)
        if tc:
            return tc

    install_hint = (
        "Install MinGW-w64 or LLVM (clang + ld.lld + llvm-objcopy), and add to PATH."
        if platform.system() == "Windows" else
        "Install cross-tools or clang/lld:\n"
        "  Debian/Ubuntu: apt install gcc-mingw-w64-x86-64 clang lld llvm\n"
        "  Fedora:        dnf install mingw64-gcc clang lld llvm\n"
        "  Arch:          pacman -S mingw-w64-gcc clang lld llvm"
    )
    raise BpatchToolchainError(
        f"Could not find a PE x86_64 payload toolchain.\n{install_hint}"
    )


def find_toolchain(pe: bool, arch: str,
                   cc_override:      str = "",
                   ld_override:      str = "",
                   objcopy_override: str = "",
                   toolchain_hint:   str = "auto") -> tuple[str, str, str]:
    """
    Resolve (cc, ld, objcopy) respecting all override layers.
    Raises BpatchToolchainError when something cannot be resolved.
    """
    env_cc, env_ld, env_oc = env_toolchain_overrides(pe, arch)
    if not cc_override:      cc_override      = env_cc
    if not ld_override:      ld_override      = env_ld
    if not objcopy_override: objcopy_override = env_oc

    cc = ""
    if cc_override:
        cc = resolve_exe(cc_override)
        if not cc:
            raise BpatchToolchainError(f"--cc not found: {cc_override}")

    ld = ""
    if ld_override:
        ld = resolve_exe(ld_override)
        if not ld:
            raise BpatchToolchainError(f"--ld not found: {ld_override}")
    elif cc:
        ld_names, _ = prefer_by_cc(cc)
        ld = resolve_near(cc, ld_names)

    oc = ""
    if objcopy_override:
        oc = resolve_exe(objcopy_override)
        if not oc:
            raise BpatchToolchainError(f"--objcopy not found: {objcopy_override}")
    elif cc:
        _, oc_names = prefer_by_cc(cc)
        oc = resolve_near(cc, oc_names)

    # Fill remaining pieces from auto-discovery
    if not cc or not ld or not oc:
        auto_cc, auto_ld, auto_oc = auto_toolchain(pe, arch, toolchain_hint=toolchain_hint)
        if not cc:
            cc = auto_cc
        if not ld:
            ld_names, _ = prefer_by_cc(cc)
            ld = resolve_near(cc, ld_names) or auto_ld
        if not oc:
            _, oc_names = prefer_by_cc(cc)
            oc = resolve_near(cc, oc_names) or auto_oc

    if not oc:
        raise BpatchToolchainError(
            "Failed to resolve payload objcopy. "
            "Provide an explicit value with --objcopy."
        )

    return cc, ld, oc


def find_nm_tool(pe: bool, arch: str,
                 cc_override:    str = "",
                 toolchain_hint: str = "auto") -> str:
    """Locate an nm/llvm-nm binary matching the target arch/format."""
    candidates: list[str] = []

    if cc_override:
        cc = resolve_exe(cc_override)
        if cc:
            pfx = infer_tool_prefix_from_cc(cc)
            if pfx:
                candidates += [pfx + "nm", pfx + "llvm-nm"]
            candidates += ["llvm-nm", "nm"]

    # Derive nm from the selected payload toolchain (suppressing output)
    try:
        cc, _, _ = find_toolchain(pe, arch, cc_override=cc_override,
                                  toolchain_hint=toolchain_hint)
        pfx = infer_tool_prefix_from_cc(cc)
        if pfx:
            candidates += [pfx + "nm", pfx + "llvm-nm"]
    except BpatchToolchainError:
        pass

    # Arch/format family fallbacks
    if pe and arch == "x86_64":
        candidates += ["x86_64-w64-mingw32-nm", "x86_64-unknown-w64-mingw32-nm"]
    if (not pe) and arch == "x86_64":
        candidates += ["x86_64-linux-gnu-nm", "x86_64-pc-linux-gnu-nm",
                       "x86_64-unknown-linux-gnu-nm"]
    if (not pe) and arch == "aarch64":
        candidates += ["aarch64-linux-gnu-nm", "aarch64-none-linux-gnu-nm",
                       "aarch64-unknown-linux-gnu-nm", "aarch64-linux-android-nm",
                       "llvm-nm"]

    candidates += ["llvm-nm", "nm"]
    for c in dedupe_keep_order(candidates):
        found = resolve_exe(c)
        if found:
            return found
    return ""
