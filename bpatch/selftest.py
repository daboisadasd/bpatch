"""
--self-test, --doctor, and --bootstrap implementations.
"""

import contextlib
import io
import os
import platform
import subprocess
import tempfile
from pathlib import Path

from .errors import BpatchToolchainError
from .inject import inject
from .log import info, ok, warn
from .symbols import resolve_symbol_address
from .toolchain import find_toolchain, env_toolchain_overrides
from .utils import resolve_exe, dedupe_keep_order


# ---------------------------------------------------------------------------
# Host compiler detection (for building the self-test *target*, not payload)
# ---------------------------------------------------------------------------

_GCC_HOST_VERSIONS  = list(range(16, 11, -1))
_CLANG_HOST_VERSIONS = list(range(22, 14, -1))


def _find_host_c_compiler(pe: bool, arch: str) -> str:
    base = ["cc", "gcc", "clang"]
    if pe:
        base = ["gcc", "clang", "cc",
                "x86_64-w64-mingw32-gcc", "x86_64-unknown-w64-mingw32-gcc"]
    base += (
        [f"clang-{v}" for v in _CLANG_HOST_VERSIONS]
        + [f"gcc-{v}" for v in _GCC_HOST_VERSIONS]
    )
    for cand in dedupe_keep_order(base):
        found = resolve_exe(cand)
        if found:
            return found
    # Last resort: use the payload toolchain compiler
    try:
        cc, _, _ = find_toolchain(pe, arch)
        return cc
    except BpatchToolchainError:
        pass
    raise BpatchToolchainError(
        "Could not find a host C compiler for --self-test.\n"
        "Run: bpatch --bootstrap  (or install gcc/clang manually)"
    )


def _pick_host_selftest_profile() -> tuple[str, str]:
    sysname = platform.system()
    mach    = platform.machine().lower()
    if sysname == "Windows":
        if any(k in mach for k in ("amd64", "x86_64")):
            return "PE", "x86_64"
        raise BpatchToolchainError(
            f"--self-test on Windows only supports x86_64 hosts (got {mach})"
        )
    if sysname == "Linux":
        if any(k in mach for k in ("amd64", "x86_64")):
            return "ELF", "x86_64"
        if any(k in mach for k in ("aarch64", "arm64")):
            return "ELF", "aarch64"
        raise BpatchToolchainError(
            f"--self-test on Linux supports x86_64/aarch64 hosts (got {mach})"
        )
    raise BpatchToolchainError(
        f"--self-test is not supported on {sysname} yet"
    )


# ---------------------------------------------------------------------------
# --self-test
# ---------------------------------------------------------------------------

def self_test(
    toolchain_hint:   str = "auto",
    target_override:  str = "",
    cc_override:      str = "",
    ld_override:      str = "",
    objcopy_override: str = "",
) -> int:
    fmt, arch = _pick_host_selftest_profile()
    pe = (fmt == "PE")
    info(f"[*] Running self-test profile: {fmt} {arch}")

    host_cc = _find_host_c_compiler(pe, arch)
    info(f"[*] Host compiler for target build: {host_cc}")

    with tempfile.TemporaryDirectory(prefix="bpatch_selftest_") as td:
        tdir        = Path(td)
        target_c    = tdir / "selftest_target.c"
        payload_c   = tdir / "selftest_payload.c"
        target_bin  = tdir / ("selftest_target.exe" if pe else "selftest_target")
        patched_bin = tdir / ("selftest_target.patched.exe" if pe else "selftest_target.patched")
        marker      = tdir / "selftest_marker.txt"

        marker_literal = str(marker).replace("\\", "\\\\")
        payload_src = (
            f'void payload(void) {{\n'
            f'    char out[] = "{marker_literal}";\n'
            f'    dump_str(ARG1_PTR(char), out);\n'
            f'}}\n'
        )

        target_src = """\
#include <stdio.h>
#include <string.h>

#if defined(_MSC_VER)
#define BP_NOINLINE __declspec(noinline)
#else
#define BP_NOINLINE __attribute__((noinline))
#endif

BP_NOINLINE int hook_me(const char *msg) {
    volatile int n = (int)strlen(msg);
    return n + 7;
}

int main(void) {
    const char *s = "BPATCH_SELFTEST";
    int v = hook_me(s);
    printf("SELFTEST:%d\\n", v);
    return 0;
}
"""
        target_c.write_text(target_src,    encoding="utf-8")
        payload_c.write_text(payload_src, encoding="utf-8")

        cc_cmd = [host_cc, "-O0", "-fno-stack-protector",
                  str(target_c), "-o", str(target_bin)]
        if not pe:
            cc_cmd.insert(1, "-no-pie")
        info("[*] Building self-test target...")
        r = subprocess.run(cc_cmd, capture_output=True, text=True)
        if r.returncode != 0:
            warn("[!] Self-test target build failed:")
            warn(r.stderr or r.stdout)
            return 1

        if marker.exists():
            marker.unlink()

        info("[*] Running baseline target...")
        base = subprocess.run([str(target_bin)], capture_output=True,
                              text=True, cwd=str(tdir))
        if base.returncode != 0:
            warn("[!] Baseline target run failed.")
            warn(base.stderr or base.stdout)
            return 1
        base_out = base.stdout.strip()
        info(f"[*] Baseline output: {base_out}")

        target_va = resolve_symbol_address(
            target_bin, "hook_me", fmt, arch,
            cc_override=host_cc, toolchain_hint=toolchain_hint,
        )

        info("[*] Injecting payload into self-test target...")
        inject(
            target_bin, target_va, payload_c, patched_bin,
            cc_override=cc_override, ld_override=ld_override,
            objcopy_override=objcopy_override,
            payload_opt="O2", toolchain_hint=toolchain_hint,
            target_override=target_override,
        )

        info("[*] Running patched target...")
        patched = subprocess.run([str(patched_bin)], capture_output=True,
                                 text=True, cwd=str(tdir))
        if patched.returncode != 0:
            warn("[!] Patched target run failed.")
            warn(patched.stderr or patched.stdout)
            return 1
        patched_out = patched.stdout.strip()
        info(f"[*] Patched output: {patched_out}")

        if base_out != patched_out:
            warn("[!] Self-test FAILED: patched output differs from baseline.")
            return 1
        if not marker.exists():
            warn("[!] Self-test FAILED: payload marker file not written.")
            return 1
        marker_text = marker.read_text(encoding="utf-8", errors="replace").strip()
        if marker_text != "BPATCH_SELFTEST":
            warn(f"[!] Self-test FAILED: payload marker unexpected: {marker_text!r}")
            return 1

        ok("[+] Self-test passed.")
        ok(f"    marker: {marker}")
        return 0


# ---------------------------------------------------------------------------
# --doctor
# ---------------------------------------------------------------------------

def doctor() -> int:
    info("[*] bpatch toolchain doctor")
    info(f"[*] host: {platform.system()} {platform.machine()}")
    print()

    checks = [
        ("ELF x86_64",  False, "x86_64"),
        ("ELF aarch64", False, "aarch64"),
        ("PE x86_64",   True,  "x86_64"),
    ]

    any_ok = False
    for label, pe, arch in checks:
        buf_out, buf_err = io.StringIO(), io.StringIO()
        ok_flag = False
        cc = ld_ = oc = ""
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            try:
                cc, ld_, oc = find_toolchain(pe, arch)
                ok_flag = True
            except BpatchToolchainError:
                ok_flag = False

        if ok_flag:
            any_ok = True
            link_mode = "ld" if ld_ else "cc-driver"
            ok(f"[OK]   {label:12s}  cc={cc}  ld={ld_ or '(compiler driver)'}  "
               f"objcopy={oc}  link-mode={link_mode}")
        else:
            details = (buf_out.getvalue() + "\n" + buf_err.getvalue()).splitlines()
            reason  = next(
                (ln.strip() for ln in details if ln.strip().startswith("[!")), # noqa
                "toolchain not found",
            )
            warn(f"[MISS] {label:12s}  {reason}")

    print()
    if any_ok:
        ok("[+] At least one payload toolchain is ready.")
        info("    Use --toolchain gcc|clang to prefer a compiler family.")
        info("    Use --cc/--ld/--objcopy or BPATCH_* env vars to pin exact tools.")
        return 0
    warn("[!] No usable payload toolchains detected.")
    return 1


# ---------------------------------------------------------------------------
# --bootstrap
# ---------------------------------------------------------------------------

def _build_bootstrap_commands() -> list[list[str]]:
    sysname = platform.system()
    cmds: list[list[str]] = []

    if sysname == "Windows":
        if resolve_exe("winget"):
            cmds += [
                ["winget", "install", "-e", "--id", "LLVM.LLVM",
                 "--accept-package-agreements", "--accept-source-agreements"],
                ["winget", "install", "-e", "--id", "MSYS2.MSYS2",
                 "--accept-package-agreements", "--accept-source-agreements"],
            ]
        elif resolve_exe("choco"):
            cmds.append(["choco", "install", "-y", "llvm", "mingw"])
        elif resolve_exe("scoop"):
            cmds.append(["scoop", "install", "llvm", "mingw"])
        return cmds

    if sysname == "Linux":
        if resolve_exe("apt-get"):
            cmds += [
                ["sudo", "apt-get", "update"],
                ["sudo", "apt-get", "install", "-y",
                 "build-essential", "clang", "lld", "llvm", "binutils",
                 "gcc-mingw-w64-x86-64", "binutils-mingw-w64-x86-64"],
            ]
        elif resolve_exe("dnf"):
            cmds.append(["sudo", "dnf", "install", "-y",
                         "gcc", "clang", "lld", "llvm", "binutils", "mingw64-gcc"])
        elif resolve_exe("pacman"):
            cmds.append(["sudo", "pacman", "-S", "--needed", "--noconfirm",
                         "base-devel", "clang", "lld", "llvm", "binutils",
                         "mingw-w64-gcc"])
        return cmds

    if sysname == "Darwin":
        if resolve_exe("brew"):
            cmds.append(["brew", "install", "llvm", "mingw-w64", "binutils"])
        return cmds

    return cmds


def bootstrap(yes: bool = False) -> int:
    info("[*] bpatch bootstrap")
    info(f"[*] host: {platform.system()} {platform.machine()}")
    print()

    cmds = _build_bootstrap_commands()
    if not cmds:
        warn("[!] No known package-manager bootstrap path for this host.")
        info("    Use --doctor to inspect missing toolchains and install manually.")
        return doctor()

    info("[*] Planned bootstrap commands:")
    for c in cmds:
        info("    " + " ".join(c))
    print()

    if not yes:
        info("[*] Dry-run only. Re-run with --yes to execute these commands.")
        print()
        return doctor()

    for c in cmds:
        info("[*] Running: " + " ".join(c))
        r = subprocess.run(c, capture_output=True, text=True)
        if r.returncode != 0:
            warn(f"[!] Command failed (exit {r.returncode}): {' '.join(c)}")
            err = (r.stderr or "").strip()
            out_t = (r.stdout or "").strip()
            if err:
                warn(err)
            elif out_t:
                warn(out_t)
            info("[*] Continuing with remaining bootstrap commands...")

    print()
    return doctor()
