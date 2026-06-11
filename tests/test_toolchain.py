"""
Unit tests for bpatch.toolchain — pure logic functions only.
No real compilers are invoked; shutil.which is mocked where needed.
"""
import os
import platform
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from bpatch.toolchain import (
    infer_tool_prefix_from_cc,
    infer_cc_target_flags,
    infer_ld_target_flags,
    ordered_candidates,
    prefer_by_cc,
    env_toolchain_overrides,
    _LD_LLD,
    _LD_BFD,
    _OC_LLVM,
    _OC_GNU,
)
from bpatch.errors import BpatchToolchainError


# ---------------------------------------------------------------------------
# infer_tool_prefix_from_cc
# ---------------------------------------------------------------------------

class TestInferToolPrefix:
    def test_mingw_gcc_prefix(self):
        pfx = infer_tool_prefix_from_cc("x86_64-w64-mingw32-gcc")
        assert pfx == "x86_64-w64-mingw32-"

    def test_cross_clang_versioned(self):
        pfx = infer_tool_prefix_from_cc("x86_64-linux-gnu-clang-15")
        assert pfx == "x86_64-linux-gnu-"

    def test_aarch64_gcc_prefix(self):
        pfx = infer_tool_prefix_from_cc("aarch64-linux-gnu-gcc")
        assert pfx == "aarch64-linux-gnu-"

    def test_plain_clang_no_prefix(self):
        pfx = infer_tool_prefix_from_cc("clang")
        assert pfx == ""

    def test_plain_gcc_no_prefix(self):
        pfx = infer_tool_prefix_from_cc("gcc")
        assert pfx == ""

    def test_full_path_extracts_prefix(self):
        pfx = infer_tool_prefix_from_cc("/usr/bin/x86_64-linux-gnu-gcc")
        assert pfx == "x86_64-linux-gnu-"

    def test_clang_with_version_only(self):
        """clang-15 has no cross prefix."""
        pfx = infer_tool_prefix_from_cc("clang-15")
        assert pfx == ""

    def test_windows_exe_extension_stripped(self):
        pfx = infer_tool_prefix_from_cc("x86_64-w64-mingw32-gcc.exe")
        assert pfx == "x86_64-w64-mingw32-"


# ---------------------------------------------------------------------------
# infer_cc_target_flags
# ---------------------------------------------------------------------------

class TestInferCcTargetFlags:
    def test_plain_clang_pe_x86_64(self):
        flags = infer_cc_target_flags("clang", pe=True, arch="x86_64")
        assert flags == ["--target=x86_64-w64-windows-gnu"]

    def test_plain_clang_elf_aarch64(self):
        flags = infer_cc_target_flags("clang", pe=False, arch="aarch64")
        assert flags == ["--target=aarch64-linux-gnu"]

    def test_plain_clang_elf_x86_64(self):
        """No target flag needed for native x86_64 Linux."""
        flags = infer_cc_target_flags("clang", pe=False, arch="x86_64")
        assert flags == []

    def test_cross_wrapper_no_extra_flag(self):
        """x86_64-w64-mingw32-clang already encodes the target."""
        flags = infer_cc_target_flags(
            "x86_64-w64-mingw32-clang", pe=True, arch="x86_64"
        )
        assert flags == []

    def test_gcc_no_target_flag(self):
        """gcc does not accept --target; function should return []."""
        flags = infer_cc_target_flags("gcc", pe=True, arch="x86_64")
        assert flags == []

    def test_target_override_wins(self):
        flags = infer_cc_target_flags(
            "clang", pe=False, arch="x86_64",
            target_override="x86_64-unknown-linux-musl"
        )
        assert flags == ["--target=x86_64-unknown-linux-musl"]

    def test_clang_versioned_elf_x86_64(self):
        """clang-15 on native x86_64 Linux → no flag."""
        flags = infer_cc_target_flags("clang-15", pe=False, arch="x86_64")
        assert flags == []


# ---------------------------------------------------------------------------
# infer_ld_target_flags
# ---------------------------------------------------------------------------

class TestInferLdTargetFlags:
    def test_pe_x86_64_plain_ld_needs_m(self):
        flags = infer_ld_target_flags("ld", "clang", pe=True, arch="x86_64")
        assert flags == ["-m", "i386pep"]

    def test_pe_x86_64_lld_needs_m(self):
        flags = infer_ld_target_flags("ld.lld", "clang", pe=True, arch="x86_64")
        assert flags == ["-m", "i386pep"]

    def test_pe_x86_64_mingw_cc_no_m(self):
        """MinGW-prefixed cc already handles the emulation."""
        flags = infer_ld_target_flags(
            "ld", "x86_64-w64-mingw32-gcc", pe=True, arch="x86_64"
        )
        assert flags == []

    def test_pe_x86_64_mingw_ld_no_m(self):
        """MinGW ld does not need -m."""
        flags = infer_ld_target_flags(
            "x86_64-w64-mingw32-ld", "gcc", pe=True, arch="x86_64"
        )
        assert flags == []

    def test_elf_x86_64_no_flags(self):
        flags = infer_ld_target_flags("ld", "gcc", pe=False, arch="x86_64")
        assert flags == []

    def test_pe_aarch64_no_flags(self):
        """PE aarch64 is unsupported but the function itself returns [] for it."""
        flags = infer_ld_target_flags("ld", "clang", pe=True, arch="aarch64")
        assert flags == []


# ---------------------------------------------------------------------------
# ordered_candidates
# ---------------------------------------------------------------------------

class TestOrderedCandidates:
    _candidates = [
        ("gcc",   ("ld",),     ("objcopy",)),
        ("clang", ("ld.lld",), ("llvm-objcopy",)),
        ("gcc-13",("ld",),     ("objcopy",)),
        ("clang-15", ("ld.lld",), ("llvm-objcopy",)),
    ]

    def test_auto_preserves_order(self):
        result = ordered_candidates(self._candidates, "auto")
        assert result == self._candidates

    def test_hint_clang_promotes_clang(self):
        result = ordered_candidates(self._candidates, "clang")
        names = [c[0] for c in result]
        # clang entries should appear before gcc entries
        clang_idx = [i for i, n in enumerate(names) if "clang" in n]
        gcc_idx   = [i for i, n in enumerate(names) if "gcc"   in n]
        assert max(clang_idx) < min(gcc_idx)

    def test_hint_gcc_promotes_gcc(self):
        result = ordered_candidates(self._candidates, "gcc")
        names = [c[0] for c in result]
        gcc_idx   = [i for i, n in enumerate(names) if "gcc"   in n]
        clang_idx = [i for i, n in enumerate(names) if "clang" in n]
        assert max(gcc_idx) < min(clang_idx)

    def test_hint_clang_all_remain(self):
        result = ordered_candidates(self._candidates, "clang")
        assert len(result) == len(self._candidates)


# ---------------------------------------------------------------------------
# prefer_by_cc
# ---------------------------------------------------------------------------

class TestPreferByCc:
    def test_clang_prefers_lld(self):
        ld_cands, oc_cands = prefer_by_cc("clang")
        assert ld_cands[0] in ("ld.lld", "lld")

    def test_gcc_prefers_bfd(self):
        ld_cands, oc_cands = prefer_by_cc("gcc")
        assert ld_cands[0] in ("ld", "ld.bfd")

    def test_cross_clang_prefers_lld(self):
        ld_cands, oc_cands = prefer_by_cc("x86_64-linux-gnu-clang-15")
        assert ld_cands[0] in ("ld.lld", "lld")

    def test_cross_gcc_prefers_bfd(self):
        ld_cands, oc_cands = prefer_by_cc("aarch64-linux-gnu-gcc")
        assert ld_cands[0] in ("ld", "ld.bfd")

    def test_clang_objcopy_prefers_llvm(self):
        _, oc_cands = prefer_by_cc("clang")
        assert oc_cands[0] == "llvm-objcopy"

    def test_gcc_objcopy_prefers_gnu(self):
        _, oc_cands = prefer_by_cc("gcc")
        assert oc_cands[0] == "objcopy"


# ---------------------------------------------------------------------------
# env_toolchain_overrides
# ---------------------------------------------------------------------------

class TestEnvToolchainOverrides:
    def test_no_env_returns_empty(self, monkeypatch):
        for var in ("BPATCH_CC", "BPATCH_LD", "BPATCH_OBJCOPY",
                    "BPATCH_ELF_X86_64_CC", "BPATCH_ELF_X86_64_LD",
                    "BPATCH_ELF_X86_64_OBJCOPY"):
            monkeypatch.delenv(var, raising=False)
        cc, ld, oc = env_toolchain_overrides(pe=False, arch="x86_64")
        assert cc == "" and ld == "" and oc == ""

    def test_global_cc_returned(self, monkeypatch):
        monkeypatch.setenv("BPATCH_CC", "my-clang")
        cc, ld, oc = env_toolchain_overrides(pe=False, arch="x86_64")
        assert cc == "my-clang"

    def test_scoped_overrides_global(self, monkeypatch):
        monkeypatch.setenv("BPATCH_CC",              "global-cc")
        monkeypatch.setenv("BPATCH_ELF_X86_64_CC",   "scoped-cc")
        cc, ld, oc = env_toolchain_overrides(pe=False, arch="x86_64")
        assert cc == "scoped-cc"

    def test_pe_scope_key(self, monkeypatch):
        monkeypatch.setenv("BPATCH_PE_X86_64_CC", "mingw-clang")
        monkeypatch.delenv("BPATCH_CC", raising=False)
        cc, ld, oc = env_toolchain_overrides(pe=True, arch="x86_64")
        assert cc == "mingw-clang"

    def test_legacy_aarch64_env(self, monkeypatch):
        """BPATCH_AARCH64_CC is a legacy alias for ELF aarch64."""
        monkeypatch.setenv("BPATCH_AARCH64_CC", "aarch64-gcc")
        monkeypatch.delenv("BPATCH_CC", raising=False)
        monkeypatch.delenv("BPATCH_ELF_AARCH64_CC", raising=False)
        cc, ld, oc = env_toolchain_overrides(pe=False, arch="aarch64")
        assert cc == "aarch64-gcc"

    def test_legacy_aarch64_not_for_pe(self, monkeypatch):
        """BPATCH_AARCH64_CC must NOT bleed into PE scope."""
        monkeypatch.setenv("BPATCH_AARCH64_CC", "aarch64-gcc")
        monkeypatch.delenv("BPATCH_CC", raising=False)
        monkeypatch.delenv("BPATCH_PE_AARCH64_CC", raising=False)
        cc, ld, oc = env_toolchain_overrides(pe=True, arch="aarch64")
        assert cc == ""
