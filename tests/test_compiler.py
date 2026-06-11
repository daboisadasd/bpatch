"""
Unit tests for bpatch.compiler — pure-logic helpers and mocked subprocess paths.

Real compiler invocations are skipped (they need a real toolchain on PATH).
The unit tests cover:
  - _rewrite_payload_signature()
  - _find_bad_relocs()
  - find_payload_offset() with a mocked nm subprocess
"""
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from bpatch.compiler import (
    _rewrite_payload_signature,
    _find_bad_relocs,
    find_payload_offset,
)
from bpatch.errors import BpatchCompileError


# ---------------------------------------------------------------------------
# _rewrite_payload_signature
# ---------------------------------------------------------------------------

class TestRewritePayloadSignature:
    EXPECTED_SIG = "__attribute__((used)) void payload(ctx_t *ctx)"

    def test_plain_void(self):
        src = "void payload() {\n    return;\n}\n"
        out = _rewrite_payload_signature(src)
        assert self.EXPECTED_SIG in out

    def test_explicit_void_param(self):
        src = "void payload(void) {\n    return;\n}\n"
        out = _rewrite_payload_signature(src)
        assert self.EXPECTED_SIG in out

    def test_extra_whitespace(self):
        src = "void  payload  (  void  ) {}"
        out = _rewrite_payload_signature(src)
        assert self.EXPECTED_SIG in out

    def test_tabs_between_tokens(self):
        src = "void\tpayload\t(\tvoid\t) {}"
        out = _rewrite_payload_signature(src)
        assert self.EXPECTED_SIG in out

    def test_unrelated_function_untouched(self):
        src = "void helper() {}\nvoid payload() {}"
        out = _rewrite_payload_signature(src)
        assert "void helper()" in out
        assert self.EXPECTED_SIG in out

    def test_no_signature_no_change(self):
        src = "int main(void) { return 0; }"
        out = _rewrite_payload_signature(src)
        assert out == src

    def test_prototype_declaration_also_rewritten(self):
        """Forward declaration should also be rewritten."""
        src = "void payload(void);\nvoid payload(void) {}\n"
        out = _rewrite_payload_signature(src)
        assert out.count(self.EXPECTED_SIG) == 2

    def test_already_has_param_not_double_rewritten(self):
        """If signature already has ctx_t, it won't match the pattern (correct)."""
        src = "__attribute__((used)) void payload(ctx_t *ctx) {}\n"
        out = _rewrite_payload_signature(src)
        assert out == src


# ---------------------------------------------------------------------------
# _find_bad_relocs
# ---------------------------------------------------------------------------

class TestFindBadRelocs:
    _READELF_X86 = """\
Relocation section '.rela.text' at offset 0x380 contains 3 entries:
  Offset          Info           Type           Sym. Value    Sym. Name
000000000005  000300000004 R_X86_64_PLT32 0000000000000000 printf - 4
000000000010  000400000002 R_X86_64_PC32  0000000000000000 local_fn - 4
000000000020  000500000009 R_X86_64_GOTPCREL 0000000000000000 global_var - 4
"""
    _READELF_CLEAN = """\
Relocation section '.rela.text' at offset 0x180 contains 1 entry:
  000000000005  000300000002 R_X86_64_PC32 0000000000000000 some_fn - 4
"""

    def test_x86_plt_detected(self):
        bad = _find_bad_relocs(self._READELF_X86, "x86_64")
        assert any("PLT32" in b for b in bad)

    def test_x86_gotpcrel_detected(self):
        bad = _find_bad_relocs(self._READELF_X86, "x86_64")
        assert any("GOTPCREL" in b for b in bad)

    def test_x86_pc32_not_bad(self):
        """R_X86_64_PC32 is a regular relative reloc — should NOT appear in bad list."""
        bad = _find_bad_relocs(self._READELF_CLEAN, "x86_64")
        assert bad == []

    def test_empty_input(self):
        assert _find_bad_relocs("", "x86_64") == []

    def test_aarch64_got_detected(self):
        relf = "  R_AARCH64_ADR_GOT_PAGE printf\n  R_AARCH64_LD64_GOT_LO12_NC printf\n"
        bad  = _find_bad_relocs(relf, "aarch64")
        assert len(bad) == 2

    def test_aarch64_clean(self):
        relf = "  R_AARCH64_CALL26 my_helper\n"
        bad  = _find_bad_relocs(relf, "aarch64")
        assert bad == []


# ---------------------------------------------------------------------------
# find_payload_offset  (mocked nm)
# ---------------------------------------------------------------------------

class TestFindPayloadOffset:
    def _mock_run(self, nm_output: str):
        """Return a mock subprocess.run result with the given stdout."""
        m = MagicMock()
        m.stdout    = nm_output
        m.returncode = 0
        return m

    def test_finds_offset_zero(self, tmp_path):
        nm_out = "payload T 0000000000000000 0000000000000080\n"
        with patch("subprocess.run", return_value=self._mock_run(nm_out)):
            off = find_payload_offset("nm", tmp_path / "payload.o")
        assert off == 0

    def test_finds_nonzero_offset(self, tmp_path):
        nm_out = (
            "helper T 0000000000000000 0000000000000040\n"
            "payload T 0000000000000040 0000000000000080\n"
        )
        with patch("subprocess.run", return_value=self._mock_run(nm_out)):
            off = find_payload_offset("nm", tmp_path / "payload.o")
        assert off == 0x40

    def test_missing_symbol_raises(self, tmp_path):
        nm_out = "helper T 0000000000000000 0000000000000040\n"
        with patch("subprocess.run", return_value=self._mock_run(nm_out)):
            with pytest.raises(BpatchCompileError, match="payload\\(\\)"):
                find_payload_offset("nm", tmp_path / "payload.o")

    def test_undefined_payload_not_matched(self, tmp_path):
        """'payload U' (undefined) should not satisfy the T/t check."""
        nm_out = "payload U\n"
        with patch("subprocess.run", return_value=self._mock_run(nm_out)):
            with pytest.raises(BpatchCompileError):
                find_payload_offset("nm", tmp_path / "payload.o")

    def test_lowercase_t_accepted(self, tmp_path):
        """nm sometimes emits lowercase 't' for local text symbols."""
        nm_out = "payload t 0000000000000020 0000000000000010\n"
        with patch("subprocess.run", return_value=self._mock_run(nm_out)):
            off = find_payload_offset("nm", tmp_path / "payload.o")
        assert off == 0x20
