"""
Integration tests — require real toolchain(s) and/or a remote Linux host.

Markers:
  integration  — any test that calls real compilers or writes real binaries
  linux        — requires the Linux test machine at 192.168.200.6
  windows      — tests that run directly on Windows (no SSH needed)
  ssh          — specifically requires paramiko + network access

Run only fast unit tests:     pytest --ignore=tests/test_integration.py
Run all integration tests:    pytest -m integration
Run only Linux SSH tests:     pytest -m "integration and linux"
Run only Windows tests:       pytest -m "integration and windows"
"""

import os
import platform
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

import pytest

from tests.conftest import ssh_run, ssh_put, LINUX_HOST, LINUX_VENV, LINUX_VENV_BIN

REPO_ROOT = Path(__file__).parent.parent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_host_cc():
    """Return a host C compiler that is available on PATH, or None."""
    for cc in ("clang", "clang-15", "clang-14", "gcc", "cc"):
        if shutil.which(cc):
            return cc
    return None


def _find_host_nm():
    for nm in ("llvm-nm", "nm"):
        if shutil.which(nm):
            return nm
    return None


def _build_hello_elf(tmpdir: Path, cc: str) -> Path:
    """
    Compile a tiny hello-world ELF binary with a hook_me() function.
    Returns the path to the compiled binary.
    """
    src = tmpdir / "hello.c"
    out = tmpdir / "hello"
    src.write_text(
        '#include <stdio.h>\n'
        'void hook_me(int x) { printf("hook_me(%d)\\n", x); }\n'
        'int main(void) { hook_me(42); return 0; }\n',
        encoding="utf-8",
    )
    r = subprocess.run(
        [cc, "-g", "-O0", "-o", str(out), str(src)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        pytest.skip(f"Could not compile hello.c: {r.stderr}")
    return out


def _make_dummy_payload_c(tmpdir: Path) -> Path:
    """Write a minimal bpatch payload that compiles without libc."""
    p = tmpdir / "nop_payload.c"
    p.write_text(
        '#include "bpatch_rt.h"\n'
        'void payload(void) { /* no-op */ }\n',
        encoding="utf-8",
    )
    return p


# ---------------------------------------------------------------------------
# Local smoke test: does `bpatch --version` work?
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_cli_version():
    """bpatch --version exits 0 and prints the version string."""
    r = subprocess.run(
        ["python", "-m", "bpatch", "--version"],
        capture_output=True, text=True,
        cwd=str(REPO_ROOT),
    )
    assert r.returncode == 0
    assert "bpatch" in r.stdout.lower()


@pytest.mark.integration
def test_cli_doctor():
    """bpatch --doctor exits 0 or 1 (never crashes with a traceback)."""
    r = subprocess.run(
        ["python", "-m", "bpatch", "--doctor"],
        capture_output=True, text=True,
        cwd=str(REPO_ROOT),
    )
    assert r.returncode in (0, 1), f"Unexpected exit code: {r.returncode}\n{r.stderr}"
    assert "Traceback" not in r.stderr


# ---------------------------------------------------------------------------
# Dry-run injection: Linux ELF x86_64 (no SSH required — build locally)
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.skipif(platform.system() == "Windows",
                    reason="ELF binary compilation not available on Windows")
def test_elf_x86_64_dry_run_local():
    """
    Compile a tiny ELF, then inject with --dry-run.
    Verifies the full compile+inject pipeline succeeds without executing
    any payload or writing the output binary.
    """
    cc = _find_host_cc()
    if cc is None:
        pytest.skip("No C compiler found on PATH")

    with tempfile.TemporaryDirectory() as td:
        tmpdir     = Path(td)
        hello      = _build_hello_elf(tmpdir, cc)
        payload_c  = REPO_ROOT / "examples" / "dump_string.c"
        if not payload_c.exists():
            payload_c = _make_dummy_payload_c(tmpdir)

        # resolve a valid address via nm
        nm = _find_host_nm()
        if not nm:
            pytest.skip("No nm/llvm-nm on PATH")

        proc = subprocess.run([nm, str(hello)], capture_output=True, text=True)
        addr = None
        for line in proc.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[-1] == "hook_me":
                addr = int(parts[0], 16)
                break
        if addr is None:
            pytest.skip("Could not resolve hook_me symbol")

        r = subprocess.run(
            ["python", "-m", "bpatch",
             str(hello), "--at", hex(addr),
             "--payload", str(payload_c),
             "--dry-run"],
            capture_output=True, text=True,
            cwd=str(REPO_ROOT),
        )
        assert r.returncode == 0, f"bpatch dry-run failed:\n{r.stderr}"
        assert "Dry run complete" in r.stdout or "Dry run complete" in r.stderr


# ---------------------------------------------------------------------------
# Windows PE x86_64 tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.windows
@pytest.mark.skipif(platform.system() != "Windows",
                    reason="PE injection test must run on Windows")
def test_pe_x86_64_dry_run_windows():
    """
    Patch a real Windows PE binary with --dry-run and verify no crash.
    Uses calc.exe (always present) as a target.
    """
    target = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "calc.exe"
    if not target.exists():
        pytest.skip("calc.exe not found")

    # Use nm/llvm-nm if available; otherwise pick a hard-coded entry-point stub.
    nm = _find_host_nm()
    addr_hex = None
    if nm:
        proc = subprocess.run([nm, str(target)], capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[-1] in ("WinMain", "main", "wWinMain"):
                addr_hex = hex(int(parts[0], 16))
                break

    if addr_hex is None:
        # Fall back to a known-good VA from the PE header OEP (not always available)
        # Use a small synthetic PE instead — skip if no address available.
        pytest.skip("Could not resolve a PE entry-point symbol for calc.exe")

    payload_c = REPO_ROOT / "examples" / "log_regs_win.c"
    if not payload_c.exists():
        pytest.skip("log_regs_win.c example not found")

    r = subprocess.run(
        ["python", "-m", "bpatch",
         str(target), "--at", addr_hex,
         "--payload", str(payload_c),
         "--dry-run"],
        capture_output=True, text=True,
        cwd=str(REPO_ROOT),
    )
    assert r.returncode == 0, f"PE dry-run failed:\n{r.stderr}"
    assert "Traceback" not in r.stderr


# ---------------------------------------------------------------------------
# SSH Linux tests: end-to-end inject + execute
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.linux
@pytest.mark.ssh
def test_ssh_connectivity():
    """Basic smoke test: can we reach the Linux machine?"""
    rc, out, err = ssh_run("echo hello_from_bpatch", timeout=15)
    assert rc == 0, f"SSH echo failed: {err}"
    assert "hello_from_bpatch" in out


@pytest.mark.integration
@pytest.mark.linux
@pytest.mark.ssh
def test_ssh_python_available():
    """Python venv must be available on the remote."""
    rc, out, err = ssh_run(f"{LINUX_VENV_BIN} --version", timeout=15)
    assert rc == 0, f"Python not available in venv: {err}"
    assert "Python 3" in out


@pytest.mark.integration
@pytest.mark.linux
@pytest.mark.ssh
def test_ssh_bpatch_version():
    """bpatch --version works on the remote Linux host."""
    rc, out, err = ssh_run(
        f"{LINUX_VENV} -m bpatch --version 2>&1", timeout=30
    )
    assert rc == 0, f"bpatch --version failed on remote: {err}\n{out}"
    assert "bpatch" in out.lower()


@pytest.mark.integration
@pytest.mark.linux
@pytest.mark.ssh
def test_ssh_bpatch_doctor():
    """bpatch --doctor runs without traceback on remote."""
    rc, out, err = ssh_run(
        f"{LINUX_VENV} -m bpatch --doctor 2>&1", timeout=60
    )
    assert rc in (0, 1), f"Unexpected exit code {rc}: {out}"
    assert "Traceback" not in out + err


@pytest.mark.integration
@pytest.mark.linux
@pytest.mark.ssh
def test_ssh_elf_x86_64_inject_and_run():
    """
    Full end-to-end test on the remote Linux machine:
      1. Copy the repo (or a minimal subset) to the remote.
      2. Compile a tiny ELF target on the remote.
      3. Inject an example payload with bpatch.
      4. Run the patched binary and verify it exits 0.
    """
    # Check that gcc or clang is available remotely
    rc, out, _ = ssh_run("which gcc clang 2>/dev/null | head -1", timeout=15)
    if rc != 0 or not out.strip():
        pytest.skip("No C compiler on remote machine")

    # Build a tiny hello binary on the remote
    build_cmd = (
        'cat > /tmp/bpatch_hello.c <<\'EOF\'\n'
        '#include <stdio.h>\n'
        'void hook_me(int x) { printf("hook_me(%d)\\n", x); }\n'
        'int main(void) { hook_me(42); return 0; }\n'
        'EOF\n'
        'gcc -g -O0 -o /tmp/bpatch_hello /tmp/bpatch_hello.c 2>&1'
    )
    rc, out, err = ssh_run(build_cmd, timeout=30)
    if rc != 0:
        pytest.skip(f"Remote compile failed: {out}{err}")

    # Resolve hook_me address remotely
    rc, nm_out, _ = ssh_run("nm /tmp/bpatch_hello 2>/dev/null || llvm-nm /tmp/bpatch_hello", timeout=15)
    addr = None
    for line in nm_out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[-1] == "hook_me":
            try:
                addr = int(parts[0], 16)
            except ValueError:
                pass
            break
    if addr is None:
        pytest.skip("Could not resolve hook_me on remote")

    # Upload payload file
    payload_local = REPO_ROOT / "examples" / "dump_string.c"
    if not payload_local.exists():
        pytest.skip("examples/dump_string.c not found")

    ssh_put(payload_local, "/tmp/bpatch_payload.c")

    # Upload bpatch runtime header (needed during payload compile on remote)
    # Run bpatch remotely
    inject_cmd = (
        f"{LINUX_VENV} -m bpatch "
        f"/tmp/bpatch_hello --at {hex(addr)} "
        f"--payload /tmp/bpatch_payload.c "
        f"-o /tmp/bpatch_hello_patched 2>&1"
    )
    rc, out, err = ssh_run(inject_cmd, timeout=120)
    assert rc == 0, f"Remote bpatch injection failed:\n{out}"
    assert "Traceback" not in out

    # Run the patched binary
    rc, out, err = ssh_run("/tmp/bpatch_hello_patched 2>&1", timeout=30)
    # The patched binary should exit without crashing (rc 0 or non-fatal signal)
    # hook_me will still print its original output
    assert rc == 0, f"Patched binary crashed: rc={rc}\n{out}"
    assert "hook_me(42)" in out


@pytest.mark.integration
@pytest.mark.linux
@pytest.mark.ssh
def test_ssh_elf_lto_inject():
    """
    Same as above but with --lto to test the LTO pipeline on Linux.
    """
    rc, out, _ = ssh_run("which clang 2>/dev/null && which lld 2>/dev/null", timeout=15)
    if rc != 0 or not out.strip():
        pytest.skip("clang/lld not available on remote — skipping LTO test")

    rc, out, _ = ssh_run("test -f /tmp/bpatch_hello", timeout=10)
    if rc != 0:
        pytest.skip("Run test_ssh_elf_x86_64_inject_and_run first to build hello binary")

    rc, nm_out, _ = ssh_run("nm /tmp/bpatch_hello 2>/dev/null", timeout=15)
    addr = None
    for line in nm_out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[-1] == "hook_me":
            try:
                addr = int(parts[0], 16)
            except ValueError:
                pass
            break
    if addr is None:
        pytest.skip("hook_me address not resolvable")

    inject_cmd = (
        f"{LINUX_VENV} -m bpatch "
        f"/tmp/bpatch_hello --at {hex(addr)} "
        f"--payload /tmp/bpatch_payload.c "
        f"--lto --toolchain clang "
        f"-o /tmp/bpatch_hello_lto 2>&1"
    )
    rc, out, err = ssh_run(inject_cmd, timeout=120)
    assert rc == 0, f"LTO injection failed:\n{out}"
    assert "Traceback" not in out
