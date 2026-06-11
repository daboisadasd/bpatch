"""
Shared fixtures and SSH helpers for bpatch tests.
"""
import os
import struct
import sys
from pathlib import Path

import pytest

# Ensure the repo root is importable regardless of cwd
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))


# ---------------------------------------------------------------------------
# SSH helper (used by integration tests that run on the remote Linux host)
# ---------------------------------------------------------------------------

LINUX_HOST = "192.168.200.6"
LINUX_USER = "dylan"
LINUX_PASS = "Dylan"
# Always run from the project directory so the editable install's meta_path
# finder wins over PathFinder finding the repo root as a namespace package.
LINUX_VENV = "cd ~/bpatch && ~/bpatch_venv/bin/python"
LINUX_VENV_BIN = "~/bpatch_venv/bin/python"  # raw path for version checks


def ssh_run(cmd: str, timeout: int = 60) -> tuple[int, str, str]:
    """Run a command on the Linux test machine; return (rc, stdout, stderr)."""
    try:
        import paramiko
    except ImportError:
        pytest.skip("paramiko not installed — skipping SSH test")

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(LINUX_HOST, username=LINUX_USER, password=LINUX_PASS, timeout=10)
    except Exception as e:
        pytest.skip(f"Cannot connect to Linux test machine: {e}")
    _, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    rc  = stdout.channel.recv_exit_status()
    c.close()
    return rc, out, err


def ssh_put(local_path: Path, remote_path: str) -> None:
    """SCP a file to the remote host."""
    try:
        import paramiko
    except ImportError:
        pytest.skip("paramiko not installed")

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(LINUX_HOST, username=LINUX_USER, password=LINUX_PASS, timeout=10)
    except Exception as e:
        pytest.skip(f"Cannot connect to Linux test machine: {e}")
    sftp = c.open_sftp()
    sftp.put(str(local_path), remote_path)
    sftp.close()
    c.close()


# ---------------------------------------------------------------------------
# Minimal synthetic PE64 binary fixture
# ---------------------------------------------------------------------------

def _make_minimal_pe64(
    num_sections: int = 2,
    imagebase: int = 0x140000000,
    section_alignment: int = 0x1000,
    file_alignment: int = 0x200,
) -> bytes:
    """
    Build a syntactically valid minimal PE64 header + section table.
    Does not contain real code — just enough structure for header-parsing tests.
    """
    # DOS stub: MZ at 0x00, e_lfanew at 0x3C (standard offset), pad to e_lfanew.
    # Layout: MZ (2) + 0x3A zeros (58) = 0x3C, then e_lfanew (4), then pad to e_lfanew bytes.
    e_lfanew = 0x80
    dos_stub = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew) + b"\x00" * (e_lfanew - 0x40)

    # IMAGE_FILE_HEADER (20 bytes)
    machine       = 0x8664  # AMD64
    size_opt_hdr  = 0xF0    # PE32+ optional header size
    characteristics = 0x0022  # executable, large-address-aware
    file_hdr = struct.pack("<HHIIIHH",
        machine, num_sections, 0, 0, 0, size_opt_hdr, characteristics)

    # IMAGE_OPTIONAL_HEADER64 (0xF0 bytes)
    # We only fill the fields we actually parse in _pe_hdr / _pe_sections
    opt_hdr = bytearray(size_opt_hdr)
    struct.pack_into("<H",  opt_hdr, 0,   0x020B)   # PE32+ magic
    # SizeOfImage @ +56
    size_of_image = section_alignment * (num_sections + 2)
    struct.pack_into("<I",  opt_hdr, 56,  size_of_image)
    # SizeOfHeaders @ +60
    size_of_headers = file_alignment  # rounded up
    struct.pack_into("<I",  opt_hdr, 60,  size_of_headers)
    # FileAlignment @ +36
    struct.pack_into("<I",  opt_hdr, 36,  file_alignment)
    # SectionAlignment @ +32
    struct.pack_into("<I",  opt_hdr, 32,  section_alignment)
    # ImageBase @ +24
    struct.pack_into("<Q",  opt_hdr, 24,  imagebase)
    opt_hdr = bytes(opt_hdr)

    # Section table entries (40 bytes each)
    sections_blob = b""
    for i in range(num_sections):
        name      = f".sec{i}".encode("ascii").ljust(8, b"\x00")
        va        = section_alignment * (i + 1)
        vsize     = 0x500
        rawptr    = file_alignment * (i + 1)
        rawsz     = file_alignment
        chars     = 0x60000020  # CODE|EXECUTE|READ
        sec_entry = (
            name
            + struct.pack("<I", vsize)   # VirtualSize
            + struct.pack("<I", va)      # VirtualAddress
            + struct.pack("<I", rawsz)   # SizeOfRawData
            + struct.pack("<I", rawptr)  # PointerToRawData
            + struct.pack("<I", 0)       # PointerToRelocations
            + struct.pack("<I", 0)       # PointerToLinenumbers
            + struct.pack("<H", 0)       # NumberOfRelocations
            + struct.pack("<H", 0)       # NumberOfLinenumbers
            + struct.pack("<I", chars)   # Characteristics
        )
        sections_blob += sec_entry

    # Assemble: DOS stub + "PE\0\0" + file_hdr + opt_hdr + sections
    pe_sig  = b"PE\x00\x00"
    header  = dos_stub + pe_sig + file_hdr + opt_hdr + sections_blob
    # Pad to SizeOfHeaders
    header  = header.ljust(size_of_headers, b"\x00")
    # Append dummy section data
    raw_data = header + b"\x00" * (file_alignment * num_sections)
    return raw_data


@pytest.fixture
def minimal_pe64():
    """Return raw bytes of a minimal valid PE64 binary."""
    return _make_minimal_pe64()


@pytest.fixture
def minimal_pe64_packed():
    """Return a PE64 where the section table has NO free header slot."""
    # With size_of_headers = file_alignment (0x200) and many sections,
    # filling up the table so new_hdr_off + 40 > soh.
    # Easiest: make num_sections very large so the table overflows soh.
    # We fake this by tweaking soh to equal the current table end.
    raw = bytearray(_make_minimal_pe64(num_sections=3))
    # Read parsed e_lfanew, find sectbl offset, set soh = sectbl + 3*40
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    size_opt_hdr = struct.unpack_from("<H", raw, e_lfanew + 4 + 16)[0]
    sectbl = e_lfanew + 24 + size_opt_hdr
    new_soh = sectbl + 3 * 40  # exactly no room for a 4th entry
    # SizeOfHeaders is at opt_hdr + 60
    struct.pack_into("<I", raw, e_lfanew + 24 + 60, new_soh)
    return bytes(raw)
