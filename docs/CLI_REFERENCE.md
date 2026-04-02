# CLI Reference

This is a practical command reference for day-to-day use.

## Main Patch Command

```bash
python bpatch.py <binary> (--at <hex_va> | --at-symbol <name>) --payload <payload.c> [-o output]
```

## Core Options

- `--at <hex_va>`: explicit injection VA (e.g. `0x140001234`)
- `--at-symbol <name>`: resolve injection address by symbol (`nm`/`llvm-nm`)
- `--payload <file.c>`: C payload source
- `-o, --output <path>`: patched output path

## Toolchain Options

- `--toolchain auto|gcc|clang`: preferred family
- `--cc <compiler>`: explicit C compiler
- `--ld <linker>`: explicit linker
- `--objcopy <objcopy>`: explicit objcopy tool
- `--target <triple>`: force compiler target triple
- `--payload-opt O0|O1|O2|O3|Os|Oz`: payload optimization
- `--payload-cflag <flag>`: extra compile flags (repeatable)
- `--payload-ldflag <flag>`: extra linker flags (repeatable)

## Helper Commands

- `--list`: list bundled payload examples
- `--doctor`: check detectable toolchains
- `--bootstrap`: print/install bootstrap commands (dry-run unless `--yes`)
- `--self-test`: build, patch, and verify local sample flow
- `--dump-header`: dump runtime header and exit

## Environment Variables

General:

- `BPATCH_TOOLCHAIN`
- `BPATCH_TARGET`
- `BPATCH_CC`, `BPATCH_LD`, `BPATCH_OBJCOPY`

Scoped (format + arch):

- `BPATCH_ELF_X86_64_CC`, `BPATCH_ELF_X86_64_LD`, `BPATCH_ELF_X86_64_OBJCOPY`
- `BPATCH_ELF_AARCH64_CC`, `BPATCH_ELF_AARCH64_LD`, `BPATCH_ELF_AARCH64_OBJCOPY`
- `BPATCH_PE_X86_64_CC`, `BPATCH_PE_X86_64_LD`, `BPATCH_PE_X86_64_OBJCOPY`

Backward-compatible aliases:

- `BPATCH_AARCH64_CC`, `BPATCH_AARCH64_LD`, `BPATCH_AARCH64_OBJCOPY`

Extra flags:

- `BPATCH_PAYLOAD_CFLAGS`
- `BPATCH_PAYLOAD_LDFLAGS`

## Common Recipes

Patch by symbol:

```bash
python bpatch.py sample.exe --at-symbol target_func --payload my_payload.c -o sample.patched.exe
```

Force clang family without hardcoding tools:

```bash
python bpatch.py sample.exe --at-symbol target_func --payload my_payload.c --toolchain clang -o sample.patched.exe
```

Use explicit toolchain binaries:

```bash
python bpatch.py sample.exe --at 0x140001234 --payload my_payload.c \
  --cc x86_64-w64-mingw32-gcc --ld x86_64-w64-mingw32-ld --objcopy x86_64-w64-mingw32-objcopy \
  -o sample.patched.exe
```

Debug setup quickly:

```bash
python bpatch.py --doctor
python bpatch.py --self-test
```
