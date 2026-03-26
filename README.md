# bpatch

`bpatch` is a static binary injection tool for malware analysis and reverse engineering workflows.

It patches a callsite in a target binary to jump into an injected trampoline, runs a user C payload, restores context, then resumes original execution.

## Current Support

- ELF: `x86_64`, `aarch64` (Linux/Android)
- PE: `x86_64` (Windows)

## Features

- Auto-detects ELF vs PE
- Architecture backends split by file (`bpatch_arch/x86_64.py`, `bpatch_arch/aarch64.py`)
- Payload toolchain overrides:
  - `--cc`
  - `--ld`
  - `--objcopy`
  - `--payload-opt` (`O0/O1/O2/O3/Os/Oz`)
- Re-patching support (chained hooks) with unique injection section names

## Requirements

Install Python deps:

```bash
pip install -r requirements.txt
```

Toolchain requirements depend on target format/arch:

- Linux x86_64 ELF payloads: `gcc`, `ld`, `objcopy`
- Linux/Android aarch64 ELF payloads: either GNU aarch64 cross tools or Android NDK clang wrappers
- Windows PE payloads:
  - On Windows host: MinGW-w64 in PATH
  - On Linux host: `x86_64-w64-mingw32-*` tools

## Usage

```bash
python bpatch.py <binary> --at <address> --payload <payload.c> [-o output]
```

Examples:

```bash
# Windows PE
python bpatch.py stress_target.exe --at 0x140001450 --payload examples/stress_payload_win.c -o stress_patched.exe

# Linux ELF
python bpatch.py target.elf --at 0x401234 --payload examples/dump_string.c -o target.patched

# Android arm64 payload toolchain override
python bpatch.py target_arm64.elf --at 0x400123 --payload examples/dump_string.c \
  --cc aarch64-linux-android34-clang --payload-opt Oz -o target_arm64.patched

# Re-patch an already patched binary (chains hooks)
python bpatch.py stress_patched.exe --at 0x140001450 --payload examples/stress_payload_win.c -o stress_patched2.exe
```

## Repo Layout

- `bpatch.py` - main CLI and injection logic
- `bpatch_arch/` - architecture-specific stealing/fixup/trampoline code
- `examples/` - sample payloads
- `STRESS_TEST.txt` - stress test instructions
- `stress_target.c` - stress-test target program

## Notes

- Injection address (`--at`) is build-dependent; re-find it after recompiles.
- This project is intended for authorized analysis and research use.
