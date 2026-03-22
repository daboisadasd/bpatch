import struct
import sys

import capstone
import capstone.x86
import keystone


MIN_STEAL = 5   # bytes for rel32 JMP (E9 xx xx xx xx)


def steal_insns(raw: bytes, target_va: int, sec_va: int, sec_foff: int):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    foff = sec_foff + (target_va - sec_va)
    code = raw[foff: foff + 64]
    insns, total = [], 0
    for ins in md.disasm(code, target_va):
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


# Near jcc opcodes: 0F 8x = 2-byte prefix form, rel32 in last 4 bytes
_JCC_SHORT = set(range(0x70, 0x80))  # 70-7F: jcc rel8
_JCC_NEAR_2 = set(range(0x80, 0x90))  # 0F 80-8F: jcc rel32 (2-byte opcode)
# loop/loope/loopne/jcxz rel8
_LOOP_OPS = {0xE0, 0xE1, 0xE2, 0xE3}


def fixup_insns(insns, dst_va: int) -> bytes:
    """
    Re-encode stolen instructions for their new location dst_va.
    Handles:
      - RIP-relative memory operands
      - rel32 JMP (E9) and CALL (E8)
      - short JMP (EB rel8), promoted to near if needed
      - short jcc (70-7F rel8), promoted to near (0F 8x rel32) if needed
      - near jcc (0F 80-8F rel32)
      - loop/loopz/loopnz/jcxz (E0-E3 rel8) -- abort if promotion needed
        since there is no rel32 encoding for these
    """
    out = b""
    off = 0
    for ins in insns:
        raw = bytes(ins.bytes)
        new = raw
        idst = dst_va + off
        fixed = False

        # ---- RIP-relative memory operand --------------------------------
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                abs_t = ins.address + ins.size + op.mem.disp
                nd = abs_t - (idst + ins.size)
                if not (-(1 << 31) <= nd <= (1 << 31) - 1):
                    print(f"[!] RIP-rel overflow at 0x{ins.address:x}")
                    sys.exit(1)
                # Use Capstone's decoded displacement location.
                disp_off = getattr(ins, "disp_offset", 0)
                disp_sz = getattr(ins, "disp_size", 0)
                if not (disp_sz == 4 and 0 <= disp_off <= len(raw) - 4):
                    # Conservative fallback for older Capstone bindings where
                    # offsets are unavailable: only accept clear last-4-byte form.
                    disp_bytes = struct.pack("<i", op.mem.disp)
                    if len(raw) >= 4 and raw[-4:] == disp_bytes:
                        disp_off = len(raw) - 4
                    else:
                        print(f"[!] Cannot locate RIP displacement bytes at 0x{ins.address:x}")
                        sys.exit(1)
                new = raw[:disp_off] + struct.pack("<i", nd) + raw[disp_off + 4:]
                print(f"    fixup rip-rel @ 0x{ins.address:x}: {op.mem.disp:+#x} -> {nd:+#x}")
                fixed = True
                break

        if fixed:
            out += new
            off += len(new)
            continue

        b0 = raw[0]

        # ---- rel32 JMP (E9) / CALL (E8) ---------------------------------
        if b0 in (0xE8, 0xE9) and len(raw) == 5:
            abs_t = ins.address + ins.size + struct.unpack("<i", raw[1:5])[0]
            nr = abs_t - (idst + 5)
            if -(1 << 31) <= nr <= (1 << 31) - 1:
                new = bytes([b0]) + struct.pack("<i", nr)
            else:
                new = b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", abs_t)
            print(f"    fixup rel32 @ 0x{ins.address:x}: -> 0x{abs_t:x}")

        # ---- short JMP (EB rel8) ----------------------------------------
        elif b0 == 0xEB and len(raw) == 2:
            abs_t = ins.address + 2 + struct.unpack("b", raw[1:2])[0]
            nr8 = abs_t - (idst + 2)
            if -(1 << 7) <= nr8 <= (1 << 7) - 1:
                new = bytes([0xEB, nr8 & 0xFF])
            else:
                new = bytes([0xE9]) + struct.pack("<i", abs_t - (idst + 5))
            print(f"    fixup short jmp @ 0x{ins.address:x}: -> 0x{abs_t:x}")

        # ---- short jcc (70-7F rel8) -> promote to near jcc if needed ----
        elif b0 in _JCC_SHORT and len(raw) == 2:
            abs_t = ins.address + 2 + struct.unpack("b", raw[1:2])[0]
            nr8 = abs_t - (idst + 2)
            if -(1 << 7) <= nr8 <= (1 << 7) - 1:
                new = bytes([b0, nr8 & 0xFF])
            else:
                # Promote to near jcc: 0F (80 + cond) rel32
                cond = b0 - 0x70
                nr32 = abs_t - (idst + 6)
                if not (-(1 << 31) <= nr32 <= (1 << 31) - 1):
                    print(f"[!] jcc target too far at 0x{ins.address:x}")
                    sys.exit(1)
                new = bytes([0x0F, 0x80 + cond]) + struct.pack("<i", nr32)
            print(f"    fixup short jcc @ 0x{ins.address:x}: -> 0x{abs_t:x}")

        # ---- near jcc (0F 8x rel32) -------------------------------------
        elif b0 == 0x0F and len(raw) >= 6 and raw[1] in _JCC_NEAR_2:
            abs_t = ins.address + ins.size + struct.unpack("<i", raw[2:6])[0]
            nr32 = abs_t - (idst + 6)
            if not (-(1 << 31) <= nr32 <= (1 << 31) - 1):
                print(f"[!] near jcc target too far at 0x{ins.address:x}")
                sys.exit(1)
            new = bytes([0x0F, raw[1]]) + struct.pack("<i", nr32)
            print(f"    fixup near jcc @ 0x{ins.address:x}: -> 0x{abs_t:x}")

        # ---- loop/loopz/loopnz/jcxz (E0-E3 rel8) -----------------------
        elif b0 in _LOOP_OPS and len(raw) == 2:
            abs_t = ins.address + 2 + struct.unpack("b", raw[1:2])[0]
            nr8 = abs_t - (idst + 2)
            if -(1 << 7) <= nr8 <= (1 << 7) - 1:
                new = bytes([b0, nr8 & 0xFF])
            else:
                # No rel32 encoding exists for loop/jcxz - bail out
                print(
                    f"[!] Cannot relocate loop/jcxz at 0x{ins.address:x}: "
                    f"no rel32 encoding exists. Choose a different injection point."
                )
                sys.exit(1)
            print(f"    fixup loop/jcxz @ 0x{ins.address:x}: -> 0x{abs_t:x}")

        out += new
        off += len(new)
    return out


def build_section_content(inject_va: int, payload_bytes: bytes,
                          payload_off: int, stolen_insns, return_va: int,
                          abi: str = "sysv") -> tuple[bytes, bytes, bytes]:
    """
    Build the injected section:  [ prologue ][ epilogue ][ payload ]
    """
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

    if abi == "sysv":
        pbody = """\
            sub  rsp, 136
            pushfq
            push r15
            push r14
            push r13
            push r12
            push r11
            push r10
            push r9
            push r8
            push rbp
            push rdi
            push rsi
            push rdx
            push rcx
            push rbx
            push rax
            mov  rdi, rsp
        """
        rbody = """\
            pop  rax
            pop  rbx
            pop  rcx
            pop  rdx
            pop  rsi
            pop  rdi
            pop  rbp
            pop  r8
            pop  r9
            pop  r10
            pop  r11
            pop  r12
            pop  r13
            pop  r14
            pop  r15
            popfq
            add  rsp, 136
        """
    else:  # win64
        pbody = """\
            pushfq
            push r15
            push r14
            push r13
            push r12
            push r11
            push r10
            push r9
            push r8
            push rbp
            push rdi
            push rsi
            push rdx
            push rcx
            push rbx
            push rax
            mov  rcx, rsp
            sub  rsp, 40
        """
        rbody = """\
            add  rsp, 40
            pop  rax
            pop  rbx
            pop  rcx
            pop  rdx
            pop  rsi
            pop  rdi
            pop  rbp
            pop  r8
            pop  r9
            pop  r10
            pop  r11
            pop  r12
            pop  r13
            pop  r14
            pop  r15
            popfq
        """

    body, _ = ks.asm(pbody, addr=inject_va)
    body_sz = len(body)
    prologue_sz = body_sz + 5  # + call rel32

    epi_va = inject_va + prologue_sz
    restore, _ = ks.asm(rbody, addr=epi_va)
    restore = bytes(restore)

    stolen_va = epi_va + len(restore)
    fixed = fixup_insns(stolen_insns, stolen_va)

    jmp_site = stolen_va + len(fixed)
    jrel = return_va - (jmp_site + 5)
    if not (-(1 << 31) <= jrel <= (1 << 31) - 1):
        print("[!] Return JMP overflow")
        sys.exit(1)
    jmp_back = bytes([0xE9]) + struct.pack("<i", jrel)
    epilogue = restore + fixed + jmp_back

    payload_blob_va = inject_va + prologue_sz + len(epilogue)
    payload_entry_va = payload_blob_va + payload_off
    crel = payload_entry_va - (inject_va + prologue_sz)
    prologue = bytes(body) + bytes([0xE8]) + struct.pack("<i", crel)
    assert len(prologue) == prologue_sz

    return prologue, epilogue, prologue + epilogue + payload_bytes


def make_entry_patch(target_va: int, inject_va: int, stolen_sz: int) -> tuple[bytes, int, int]:
    """
    Return (full_patch_bytes, patch_len_without_nops, nop_count).
    """
    rel = inject_va - (target_va + 5)
    if -(1 << 31) <= rel <= (1 << 31) - 1:
        patch = bytes([0xE9]) + struct.pack("<i", rel)
        nops = stolen_sz - 5
    else:
        if stolen_sz < 14:
            print(f"[!] Need 14 stolen bytes for far JMP, got {stolen_sz}")
            sys.exit(1)
        patch = b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", inject_va)
        nops = stolen_sz - 14
    return patch + b"\x90" * nops, len(patch), nops

