"""
Unit tests for PE header parsing: _pe_hdr() and _pe_sections().
These tests use only the bpatch.inject_pe module and synthetic byte sequences —
no real binary, no toolchain, no LIEF.
"""
import struct
import pytest

from bpatch.inject_pe import _pe_hdr, _pe_sections, _SEC_HDR_SZ
from tests.conftest import _make_minimal_pe64


class TestPeHdr:
    def test_parses_e_lfanew(self, minimal_pe64):
        h = _pe_hdr(minimal_pe64)
        assert h["pe_off"] == 0x80

    def test_section_count(self, minimal_pe64):
        h = _pe_hdr(minimal_pe64)
        assert h["nsec"] == 2

    def test_file_alignment(self, minimal_pe64):
        h = _pe_hdr(minimal_pe64)
        assert h["fa"] == 0x200

    def test_size_of_headers(self, minimal_pe64):
        h = _pe_hdr(minimal_pe64)
        # SizeOfHeaders was set to file_alignment (0x200) in our fixture
        assert h["soh"] == 0x200

    def test_sectbl_offset(self, minimal_pe64):
        """Section table starts immediately after the optional header."""
        h = _pe_hdr(minimal_pe64)
        # pe_off + 4 (sig) + 20 (file_hdr) + 0xF0 (opt_hdr)
        expected = 0x80 + 4 + 20 + 0xF0
        assert h["sectbl"] == expected

    def test_nsec_off_points_at_nsec_field(self, minimal_pe64):
        """h['nsec_off'] should be the byte offset where NumberOfSections lives."""
        h = _pe_hdr(minimal_pe64)
        raw = minimal_pe64
        value = struct.unpack_from("<H", raw, h["nsec_off"])[0]
        assert value == h["nsec"]

    def test_soi_off_points_at_sizeofimage(self, minimal_pe64):
        h = _pe_hdr(minimal_pe64)
        raw = minimal_pe64
        value = struct.unpack_from("<I", raw, h["soi_off"])[0]
        assert value > 0  # non-zero, set in fixture


class TestPeSections:
    def test_section_count_matches_header(self, minimal_pe64):
        h    = _pe_hdr(minimal_pe64)
        secs = _pe_sections(minimal_pe64, h)
        assert len(secs) == h["nsec"] == 2

    def test_section_names(self, minimal_pe64):
        h    = _pe_hdr(minimal_pe64)
        secs = _pe_sections(minimal_pe64, h)
        assert secs[0]["name"] == ".sec0"
        assert secs[1]["name"] == ".sec1"

    def test_section_virtual_addresses_increasing(self, minimal_pe64):
        h    = _pe_hdr(minimal_pe64)
        secs = _pe_sections(minimal_pe64, h)
        assert secs[0]["va"] < secs[1]["va"]

    def test_section_rawptr_nonzero(self, minimal_pe64):
        h    = _pe_hdr(minimal_pe64)
        secs = _pe_sections(minimal_pe64, h)
        for s in secs:
            assert s["rawptr"] > 0

    def test_section_base_offset(self, minimal_pe64):
        """Each section dict's 'base' should be correctly spaced by _SEC_HDR_SZ."""
        h    = _pe_hdr(minimal_pe64)
        secs = _pe_sections(minimal_pe64, h)
        for i, s in enumerate(secs):
            assert s["base"] == h["sectbl"] + i * _SEC_HDR_SZ

    def test_three_sections(self):
        raw  = _make_minimal_pe64(num_sections=3)
        h    = _pe_hdr(raw)
        secs = _pe_sections(raw, h)
        assert len(secs) == 3
        assert secs[2]["name"] == ".sec2"

    def test_section_chars_executable(self, minimal_pe64):
        h    = _pe_hdr(minimal_pe64)
        secs = _pe_sections(minimal_pe64, h)
        for s in secs:
            assert s["chars"] == 0x60000020  # CODE|EXECUTE|READ


class TestCanAddSection:
    """Verify the 'can_add_section' logic used in inject_pe."""

    def test_room_available_in_normal_pe(self, minimal_pe64):
        h    = _pe_hdr(minimal_pe64)
        new_hdr_off = h["sectbl"] + h["nsec"] * _SEC_HDR_SZ
        can_add = (new_hdr_off + _SEC_HDR_SZ <= h["soh"])
        assert can_add is True

    def test_no_room_in_packed_pe(self, minimal_pe64_packed):
        h    = _pe_hdr(minimal_pe64_packed)
        new_hdr_off = h["sectbl"] + h["nsec"] * _SEC_HDR_SZ
        can_add = (new_hdr_off + _SEC_HDR_SZ <= h["soh"])
        assert can_add is False
