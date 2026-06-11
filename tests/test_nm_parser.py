"""
Unit tests for nm output parsing — parse_nm_symbol_address().
Tests both default and posix nm output formats, demangled names, etc.
"""
import pytest
from bpatch.symbols import parse_nm_symbol_address


NM_DEFAULT_SAMPLE = """\
0000000000000000 a payload.c
0000000000000000 d __ctor_list__
0000000000000000 N
0000000000401130 t hook_me
0000000000401000 T _start
0000000140001500 T encrypt_block
                 U printf
0000000000402000 T main
"""

NM_POSIX_SAMPLE = """\
payload.c a 0000000000000000 0000000000000000
__ctor_list__ d 0000000000000000 0000000000000001
hook_me t 0000000000401130 0000000000000042
_start T 0000000000401000 0000000000000010
encrypt_block T 0000000140001500 000000000000001a
printf U
main T 0000000000402000 0000000000000080
"""


class TestParseNmDefaultFormat:
    def test_finds_exact_symbol(self):
        va = parse_nm_symbol_address(NM_DEFAULT_SAMPLE, "hook_me")
        assert va == 0x401130

    def test_finds_uppercase_T(self):
        va = parse_nm_symbol_address(NM_DEFAULT_SAMPLE, "encrypt_block")
        assert va == 0x140001500

    def test_returns_none_for_missing_symbol(self):
        va = parse_nm_symbol_address(NM_DEFAULT_SAMPLE, "no_such_func")
        assert va is None

    def test_skips_undefined_U(self):
        """Undefined (U) symbols have no address and must not match."""
        va = parse_nm_symbol_address(NM_DEFAULT_SAMPLE, "printf")
        assert va is None

    def test_finds_main(self):
        va = parse_nm_symbol_address(NM_DEFAULT_SAMPLE, "main")
        assert va == 0x402000


class TestParseNmPosixFormat:
    def test_finds_hook_me_posix(self):
        va = parse_nm_symbol_address(NM_POSIX_SAMPLE, "hook_me")
        assert va == 0x401130

    def test_finds_encrypt_block_posix(self):
        va = parse_nm_symbol_address(NM_POSIX_SAMPLE, "encrypt_block")
        assert va == 0x140001500

    def test_returns_none_missing_posix(self):
        va = parse_nm_symbol_address(NM_POSIX_SAMPLE, "nonexistent")
        assert va is None


class TestParseNmEdgeCases:
    def test_empty_output(self):
        va = parse_nm_symbol_address("", "anything")
        assert va is None

    def test_blank_lines_ignored(self):
        nm = "\n\n0000000000401234 T my_func\n\n"
        va = parse_nm_symbol_address(nm, "my_func")
        assert va == 0x401234

    def test_underscore_prefix_not_matched(self):
        """_payload should not match when searching for 'payload'."""
        nm = "0000000000401000 T _payload\n"
        va = parse_nm_symbol_address(nm, "payload")
        assert va is None

    def test_partial_name_not_matched(self):
        """'hook' should not match 'hook_me'."""
        va = parse_nm_symbol_address(NM_DEFAULT_SAMPLE, "hook")
        assert va is None

    def test_zero_address_symbol(self):
        """A symbol at address 0 should be returned (it's valid)."""
        nm = "0000000000000000 T zero_func\n"
        va = parse_nm_symbol_address(nm, "zero_func")
        assert va == 0

    def test_windows_mangled_prefixed(self):
        """Windows sometimes prefixes symbols with leading underscore."""
        nm = "0000000140001234 T _MyFunction\n"
        va = parse_nm_symbol_address(nm, "_MyFunction")
        assert va == 0x140001234
