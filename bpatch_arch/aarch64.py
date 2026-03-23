import struct
import sys

import capstone
import capstone.arm64
import keystone


MIN_STEAL = 20  # absolute jump patch is 5 instructions (20 bytes)
_NOP_WORD = 0xD503201F


def steal_insns(raw: bytes, target_va: int, sec_va: int, sec_foff: int):
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    foff = sec_foff + (target_va - sec_va)
    code = raw[foff: foff + 80]
    insns, total = [], 0
    for ins in md.disasm(code, target_va):
        if ins.size != 4:
            print(f"[!] Unexpected ARM64 instruction size {ins.size} at 0x{ins.address:x}")
            sys.exit(1)
        insns.append(ins)
        total += ins.size
        if total >= MIN_STEAL:
            break
    if total < MIN_STEAL:
        print(f"[!] Only {total} bytes at 0x{target_va:x}, need {MIN_STEAL}")
        sys.exit(1)
    print(f"[+] stealing {total} bytes ({len(insns)} instrs) from 0x{target_va:x}:")
    for i in insns:
        print(f"    0x{i.address:x}:  {i.mnemonic:10s} {i.op_str}")
    return insns, total


def _needs_reloc(ins) -> bool:
    m = ins.mnemonic.lower()
    if capstone.CS_GRP_JUMP in ins.groups or capstone.CS_GRP_CALL in ins.groups:
        return True
    if m in ("adr", "adrp"):
        return True
    # Literal loads/prfm are PC-relative when operand is immediate form (not [base,...]).
    if m in ("ldr", "ldrsw", "prfm") and "[" not in ins.op_str and "#" in ins.op_str:
        return True
    return False


def fixup_insns(insns, dst_va: int) -> bytes:
    """
    Re-encode stolen ARM64 instructions at a new address.
    We rely on Keystone re-assembly to re-calculate PC-relative immediates.
    """
    ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
    out = b""
    off = 0
    for ins in insns:
        raw = bytes(ins.bytes)
        idst = dst_va + off
        asm = f"{ins.mnemonic} {ins.op_str}".strip()
        new = None

        try:
            enc, _ = ks.asm(asm, addr=idst)
            enc_b = bytes(enc)
            if len(enc_b) == 4:
                new = enc_b
        except Exception:
            new = None

        if new is None:
            if _needs_reloc(ins):
                print(f"[!] Cannot relocate ARM64 instruction at 0x{ins.address:x}: {asm}")
                sys.exit(1)
            new = raw

        if len(new) != 4:
            print(f"[!] Relocated ARM64 instruction has invalid size at 0x{ins.address:x}")
            sys.exit(1)

        if new != raw and _needs_reloc(ins):
            print(f"    fixup arm64 @ 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")

        out += new
        off += len(new)
    return out


def _abs_branch_bytes(target_va: int, link: bool = False, reg: str = "x17") -> bytes:
    """
    Emit an absolute branch/call:
      movz reg, imm16
      movk reg, imm16, lsl #16
      movk reg, imm16, lsl #32
      movk reg, imm16, lsl #48
      br/blr reg
    """
    ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
    i0 = (target_va >> 0) & 0xFFFF
    i1 = (target_va >> 16) & 0xFFFF
    i2 = (target_va >> 32) & 0xFFFF
    i3 = (target_va >> 48) & 0xFFFF
    tail = "blr" if link else "br"
    asm = f"""
        movz {reg}, #{i0}
        movk {reg}, #{i1}, lsl #16
        movk {reg}, #{i2}, lsl #32
        movk {reg}, #{i3}, lsl #48
        {tail} {reg}
    """
    enc, _ = ks.asm(asm)
    b = bytes(enc)
    if len(b) != 20:
        print("[!] Internal error: unexpected ARM64 absolute branch size")
        sys.exit(1)
    return b


def _rel_branch_bytes(src_va: int, target_va: int, link: bool = False) -> bytes | None:
    """
    Try to emit a PC-relative branch/call (b/bl).
    Returns encoded bytes on success, or None if out of range/failed.
    """
    ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
    op = "bl" if link else "b"
    try:
        enc, _ = ks.asm(f"{op} 0x{target_va:x}", addr=src_va)
    except Exception:
        return None
    b = bytes(enc)
    if len(b) != 4:
        return None
    return b


def build_section_content(inject_va: int, payload_bytes: bytes,
                          payload_off: int, stolen_insns, return_va: int,
                          abi: str = "sysv") -> tuple[bytes, bytes, bytes]:
    # AArch64 backend currently targets Linux/Android ELF (AAPCS64).
    if abi != "sysv":
        print("[!] ARM64 backend currently supports ELF/Linux ABI only")
        sys.exit(1)

    ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)

    pbody = """\
        sub sp, sp, #0x100
        stp x0,  x1,  [sp, #0x00]
        stp x2,  x3,  [sp, #0x10]
        stp x4,  x5,  [sp, #0x20]
        stp x6,  x7,  [sp, #0x30]
        stp x8,  x9,  [sp, #0x40]
        stp x10, x11, [sp, #0x50]
        stp x12, x13, [sp, #0x60]
        stp x14, x15, [sp, #0x70]
        stp x16, x17, [sp, #0x80]
        stp x18, x19, [sp, #0x90]
        stp x20, x21, [sp, #0xA0]
        stp x22, x23, [sp, #0xB0]
        stp x24, x25, [sp, #0xC0]
        stp x26, x27, [sp, #0xD0]
        stp x28, x29, [sp, #0xE0]
        str x30, [sp, #0xF0]
        mrs x9, nzcv
        str x9, [sp, #0xF8]
        mov x0, sp
    """
    rbody = """\
        ldr x9, [sp, #0xF8]
        msr nzcv, x9
        ldp x0,  x1,  [sp, #0x00]
        ldp x2,  x3,  [sp, #0x10]
        ldp x4,  x5,  [sp, #0x20]
        ldp x6,  x7,  [sp, #0x30]
        ldp x8,  x9,  [sp, #0x40]
        ldp x10, x11, [sp, #0x50]
        ldp x12, x13, [sp, #0x60]
        ldp x14, x15, [sp, #0x70]
        ldp x16, x17, [sp, #0x80]
        ldp x18, x19, [sp, #0x90]
        ldp x20, x21, [sp, #0xA0]
        ldp x22, x23, [sp, #0xB0]
        ldp x24, x25, [sp, #0xC0]
        ldp x26, x27, [sp, #0xD0]
        ldp x28, x29, [sp, #0xE0]
        ldr x30, [sp, #0xF0]
        add sp, sp, #0x100
    """

    body, _ = ks.asm(pbody, addr=inject_va)
    body = bytes(body)
    body_sz = len(body)
    prologue_sz = body_sz + 4  # + BL payload

    epi_va = inject_va + prologue_sz
    restore, _ = ks.asm(rbody, addr=epi_va)
    restore = bytes(restore)

    stolen_va = epi_va + len(restore)
    fixed = fixup_insns(stolen_insns, stolen_va)
    # Prefer PIE-safe relative branch when in range; fall back to absolute branch.
    jump_back_src = stolen_va + len(fixed)
    jump_back = _rel_branch_bytes(jump_back_src, return_va, link=False)
    if jump_back is None:
        jump_back = _abs_branch_bytes(return_va, link=False)
    epilogue = restore + fixed + jump_back

    payload_blob_va = inject_va + prologue_sz + len(epilogue)
    payload_entry_va = payload_blob_va + payload_off

    call_bytes, _ = ks.asm(f"bl 0x{payload_entry_va:x}", addr=inject_va + body_sz)
    call_bytes = bytes(call_bytes)
    if len(call_bytes) != 4:
        print("[!] Internal error: ARM64 BL encoding size mismatch")
        sys.exit(1)

    prologue = body + call_bytes
    if len(prologue) != prologue_sz:
        print("[!] Internal error: ARM64 prologue size mismatch")
        sys.exit(1)

    return prologue, epilogue, prologue + epilogue + payload_bytes


def make_entry_patch(target_va: int, inject_va: int, stolen_sz: int) -> tuple[bytes, int, int]:
    # Prefer PIE-safe relative branch when in range; fall back to absolute branch.
    patch = _rel_branch_bytes(target_va, inject_va, link=False)
    if patch is None:
        patch = _abs_branch_bytes(inject_va, link=False)
    patch_len = len(patch)
    if stolen_sz < patch_len:
        print(f"[!] Need {patch_len} stolen bytes for ARM64 hook, got {stolen_sz}")
        sys.exit(1)
    extra = stolen_sz - patch_len
    if extra % 4 != 0:
        print("[!] ARM64 patch padding is not instruction-aligned")
        sys.exit(1)
    nop_count = extra // 4
    nops = struct.pack("<I", _NOP_WORD) * nop_count
    return patch + nops, patch_len, nop_count
