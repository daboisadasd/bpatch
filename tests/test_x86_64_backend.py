"""
Unit tests for the x86_64 backend: fixup_insns, make_entry_patch,
build_section_content (layout + sizes).

We use Capstone to disassemble synthetic machine code into instruction objects,
then feed those to the backend — same path the real inject pipeline takes.
"""
import struct
import pytest

import capstone
import capstone.x86
import keystone

from bpatch_arch.x86_64 import (
    fixup_insns,
    make_entry_patch,
    build_section_content,
    steal_insns,
    MIN_STEAL,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _disasm_one(bytecode: bytes, addr: int):
    """Disassemble exactly one x86-64 instruction at *addr*."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    insns = list(md.disasm(bytecode, addr))
    assert insns, f"No instructions decoded from {bytecode.hex()}"
    return insns[0]


def _disasm(bytecode: bytes, addr: int):
    """Disassemble all instructions in *bytecode* starting at *addr*."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    return list(md.disasm(bytecode, addr))


def _asm(asm_text: str, addr: int = 0) -> bytes:
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    enc, _ = ks.asm(asm_text, addr=addr)
    return bytes(enc)


# ---------------------------------------------------------------------------
# fixup_insns — RIP-relative instructions
# ---------------------------------------------------------------------------

class TestFixupRipRel:
    def test_rip_rel_load_reencoded_correctly(self):
        """
        LEA rax, [rip + 0x10]  at va=0x401000, relocated to va=0x600000.
        The displacement must change to keep the absolute target the same.
        """
        src_va = 0x401000
        # Build: LEA rax, [rip+0x10]  (absolute target = src_va + insn_size + 0x10)
        code = _asm("lea rax, [rip + 0x10]", addr=src_va)
        insn = _disasm_one(code, src_va)
        abs_target = src_va + insn.size + 0x10

        dst_va = 0x600000
        fixed  = fixup_insns([insn], dst_va)

        # Re-disassemble at dst_va to read new displacement
        new_insn = _disasm_one(fixed, dst_va)
        # op.mem.disp should now target the same abs_target
        for op in new_insn.operands:
            if op.type == capstone.x86.X86_OP_MEM:
                new_abs = dst_va + new_insn.size + op.mem.disp
                assert new_abs == abs_target, (
                    f"Expected abs_target=0x{abs_target:x}, got 0x{new_abs:x}"
                )

    def test_non_rip_rel_passthrough(self):
        """An instruction without RIP-relative operands is emitted unchanged."""
        src_va = 0x401000
        code   = _asm("nop", addr=src_va)
        insn   = _disasm_one(code, src_va)
        fixed  = fixup_insns([insn], 0x600000)
        assert fixed == bytes(insn.bytes)


# ---------------------------------------------------------------------------
# fixup_insns — branch instructions
# ---------------------------------------------------------------------------

class TestFixupBranches:
    def test_rel32_jmp_near(self):
        """
        JMP rel32 at src relocated to dst — target absolute address preserved.
        """
        src_va  = 0x401000
        abs_tgt = 0x402000
        delta   = abs_tgt - (src_va + 5)
        code    = bytes([0xE9]) + struct.pack("<i", delta)
        insn    = _disasm_one(code, src_va)

        dst_va  = 0x600000
        fixed   = fixup_insns([insn], dst_va)
        assert len(fixed) == 5
        new_delta = struct.unpack("<i", fixed[1:5])[0]
        assert dst_va + 5 + new_delta == abs_tgt

    def test_short_jmp_stays_short_when_in_range(self):
        """EB rel8 that fits in range stays as EB rel8 at new location."""
        src_va  = 0x401000
        abs_tgt = 0x401010  # close
        delta8  = abs_tgt - (src_va + 2)
        code    = bytes([0xEB, delta8 & 0xFF])
        insn    = _disasm_one(code, src_va)

        # dst close to src so target still fits in rel8
        dst_va  = 0x401050
        fixed   = fixup_insns([insn], dst_va)
        assert fixed[0] == 0xEB
        new_delta = struct.unpack("b", fixed[1:2])[0]
        assert dst_va + 2 + new_delta == abs_tgt

    def test_short_jmp_promoted_to_near_when_out_of_range(self):
        """EB rel8 that no longer fits is promoted to E9 rel32."""
        src_va  = 0x401000
        abs_tgt = src_va + 2 + 0x50  # 0x401052
        delta8  = 0x50
        code    = bytes([0xEB, delta8])
        insn    = _disasm_one(code, src_va)

        # Move far enough that abs_tgt no longer fits in rel8
        dst_va  = 0x600000
        fixed   = fixup_insns([insn], dst_va)
        assert fixed[0] == 0xE9, "Expected near JMP (0xE9) after promotion"
        new_delta = struct.unpack("<i", fixed[1:5])[0]
        assert dst_va + 5 + new_delta == abs_tgt

    def test_short_jcc_promoted_to_near(self):
        """JZ rel8 (0x74) that no longer fits is promoted to 0F 84 rel32."""
        src_va  = 0x401000
        abs_tgt = src_va + 2 + 0x10
        delta8  = 0x10
        code    = bytes([0x74, delta8])  # JZ +0x10
        insn    = _disasm_one(code, src_va)

        dst_va  = 0x600000
        fixed   = fixup_insns([insn], dst_va)
        assert fixed[0] == 0x0F and fixed[1] == 0x84, (
            f"Expected 0F 84 (near JZ), got {fixed[:2].hex()}"
        )
        new_delta = struct.unpack("<i", fixed[2:6])[0]
        assert dst_va + 6 + new_delta == abs_tgt

    def test_near_jcc_reencoded(self):
        """0F 8x rel32 jcc at src relocated to dst."""
        src_va  = 0x401000
        abs_tgt = 0x405000
        delta32 = abs_tgt - (src_va + 6)
        code    = bytes([0x0F, 0x84]) + struct.pack("<i", delta32)  # JZ rel32
        insn    = _disasm_one(code, src_va)

        dst_va  = 0x600000
        fixed   = fixup_insns([insn], dst_va)
        assert fixed[0] == 0x0F and fixed[1] == 0x84
        new_delta = struct.unpack("<i", fixed[2:6])[0]
        assert dst_va + 6 + new_delta == abs_tgt

    def test_call_rel32_reencoded(self):
        """E8 rel32 CALL at src relocated to dst."""
        src_va  = 0x401000
        abs_tgt = 0x403000
        delta   = abs_tgt - (src_va + 5)
        code    = bytes([0xE8]) + struct.pack("<i", delta)
        insn    = _disasm_one(code, src_va)

        dst_va  = 0x600000
        fixed   = fixup_insns([insn], dst_va)
        assert fixed[0] == 0xE8
        new_delta = struct.unpack("<i", fixed[1:5])[0]
        assert dst_va + 5 + new_delta == abs_tgt


# ---------------------------------------------------------------------------
# make_entry_patch
# ---------------------------------------------------------------------------

class TestMakeEntryPatch:
    def test_near_jmp_patch(self):
        """When inject_va is within ±2GB, emit E9 rel32 + NOPs."""
        target_va = 0x401000
        inject_va = 0x402000
        stolen_sz = 8  # steal 8 bytes, patch is 5, so 3 NOPs

        patch, patch_len, nop_count = make_entry_patch(target_va, inject_va, stolen_sz)

        assert patch[0] == 0xE9, "Expected E9 (JMP rel32)"
        assert patch_len == 5
        assert nop_count == 3
        assert len(patch) == stolen_sz
        assert patch[5:] == b"\x90" * 3

        # Verify relative offset
        delta = struct.unpack("<i", patch[1:5])[0]
        assert target_va + 5 + delta == inject_va

    def test_far_jmp_patch(self):
        """When inject_va is outside ±2GB, emit FF 25 + absolute addr."""
        target_va = 0x401000
        inject_va = 0xDEADBEEF_CAFEF00D  # far away
        stolen_sz = 16

        patch, patch_len, nop_count = make_entry_patch(target_va, inject_va, stolen_sz)

        assert patch[:2] == b"\xFF\x25", "Expected FF 25 (JMP [rip+0])"
        assert patch_len == 14
        assert nop_count == 2
        embedded_va = struct.unpack("<Q", patch[6:14])[0]
        assert embedded_va == inject_va

    def test_nop_count_zero_exact_fit(self):
        """With stolen_sz == 5 (exact fit), nop_count should be 0."""
        patch, patch_len, nop_count = make_entry_patch(0x401000, 0x402000, 5)
        assert nop_count == 0
        assert len(patch) == 5

    def test_insufficient_stolen_bytes_far_jmp(self):
        """Far JMP needs 14 bytes; steal of 13 should fail."""
        from bpatch_arch.x86_64 import make_entry_patch as mep
        # We can't use an inject_va outside ±2GB range with stolen_sz < 14
        # but we need to force the far-jmp path. Use an address that is >2GB away.
        target_va = 0x00000000_00401000
        inject_va = 0xFFFFFFFF_00401000  # >2GB from target
        with pytest.raises(SystemExit):
            mep(target_va, inject_va, 13)


# ---------------------------------------------------------------------------
# build_section_content — layout sanity
# ---------------------------------------------------------------------------

class TestBuildSectionContent:
    def _make_dummy_stolen(self, src_va: int = 0x401000):
        """Steal a simple multi-NOP sequence as the 'stolen instructions'."""
        code = _asm("nop\n" * 8, addr=src_va)
        return _disasm(code, src_va), len(code)

    def test_prologue_plus_epilogue_plus_payload(self):
        """
        The third return value (content) must equal prologue + epilogue + payload.
        """
        inject_va  = 0x500000
        stolen, sz = self._make_dummy_stolen(0x401000)
        payload    = b"\x90" * 64          # dummy payload
        payload_off = 0

        prologue, epilogue, content = build_section_content(
            inject_va, payload, payload_off, stolen, 0x401000 + sz
        )
        assert content == prologue + epilogue + payload

    def test_prologue_starts_with_reg_save(self):
        """SysV prologue starts with SUB RSP (0x48 0x83 0xEC ...) or PUSHFQ."""
        inject_va  = 0x500000
        stolen, sz = self._make_dummy_stolen(0x401000)
        payload    = b"\x90" * 64
        prologue, epilogue, content = build_section_content(
            inject_va, payload, 0, stolen, 0x401000 + sz
        )
        # SysV: starts with sub rsp (0x48 0x83 0xEC) or push sequence
        # Win64: starts with pushfq (0x9C)
        assert prologue[0] in (0x48, 0x9C, 0x55), (
            f"Unexpected first prologue byte: 0x{prologue[0]:02x}"
        )

    def test_win64_abi(self):
        """Win64 ABI prologue/epilogue differ from SysV."""
        inject_va  = 0x500000
        stolen, sz = self._make_dummy_stolen(0x401000)
        payload    = b"\x90" * 64
        pro_sysv, epi_sysv, _ = build_section_content(
            inject_va, payload, 0, stolen, 0x401000 + sz, abi="sysv"
        )
        pro_win64, epi_win64, _ = build_section_content(
            inject_va, payload, 0, stolen, 0x401000 + sz, abi="win64"
        )
        # Prologues differ between ABIs
        assert pro_sysv != pro_win64

    def test_payload_offset_nonzero(self):
        """When payload_off > 0, the CALL target shifts by that offset."""
        inject_va   = 0x500000
        stolen, sz  = self._make_dummy_stolen(0x401000)
        payload     = b"\xCC" * 16 + b"\x90" * 48  # 16-byte prefix then real payload
        payload_off = 16

        prologue0, _, _ = build_section_content(
            inject_va, payload, 0, stolen, 0x401000 + sz
        )
        prologueN, _, _ = build_section_content(
            inject_va, payload, payload_off, stolen, 0x401000 + sz
        )
        # The CALL rel32 in the prologue (last 5 bytes) must differ
        assert prologue0[-5:] != prologueN[-5:]


# ---------------------------------------------------------------------------
# steal_insns
# ---------------------------------------------------------------------------

class TestStealInsns:
    def test_steals_at_least_min_steal_bytes(self):
        """steal_insns must return >= MIN_STEAL total bytes."""
        target_va = 0x401000
        sec_va    = 0x401000
        sec_foff  = 0
        # Build enough NOPs to satisfy MIN_STEAL
        raw = _asm("nop\n" * 16, addr=target_va)
        insns, total = steal_insns(raw, target_va, sec_va, sec_foff)
        assert total >= MIN_STEAL
        assert len(insns) > 0

    def test_fails_on_insufficient_code(self):
        """When fewer than MIN_STEAL bytes are available, sys.exit is called."""
        raw = _asm("nop\n" * 2, addr=0x401000)  # only 2 bytes
        with pytest.raises(SystemExit):
            steal_insns(raw, 0x401000, 0x401000, 0)
