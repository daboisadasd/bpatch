# bpatch

`bpatch` is a static binary patching tool for malware analysis and reverse engineering workflows.
It patches a callsite so execution jumps into an injected trampoline, runs a user C payload, then resumes original code.

## Start Here (New to Reverse Engineering)

1. Read [docs/START_HERE.md](docs/START_HERE.md)
2. Follow [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)
3. Run `python bpatch.py --bootstrap` and `python bpatch.py --doctor`
4. Run `python bpatch.py --self-test`
5. Do the hands-on lab in [docs/FIRST_PATCH_WALKTHROUGH.md](docs/FIRST_PATCH_WALKTHROUGH.md)

## Documentation Map

- [docs/INDEX.md](docs/INDEX.md) - Structured learning path and full doc index
- [docs/START_HERE.md](docs/START_HERE.md) - Big picture, mindset, and workflow overview
- [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) - Fresh-machine setup and first successful run
- [docs/REVERSE_ENGINEERING_PRIMER.md](docs/REVERSE_ENGINEERING_PRIMER.md) - Core RE concepts you need for bpatch
- [docs/FIRST_PATCH_WALKTHROUGH.md](docs/FIRST_PATCH_WALKTHROUGH.md) - Step-by-step first patch lab
- [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) - Full command and option guide
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) - Common errors and fixes
- [docs/FAQ.md](docs/FAQ.md) - Practical questions and answers
- [docs/SECURITY_AND_ETHICS.md](docs/SECURITY_AND_ETHICS.md) - Safe and authorized usage rules
- [docs/STRESS_TEST.md](docs/STRESS_TEST.md) - Stress test for patch correctness

## Current Support

- ELF: `x86_64`, `aarch64` (Linux/Android)
- PE: `x86_64` (Windows)

## Key Features

- Format auto-detection (ELF vs PE)
- Injection by address (`--at`) or symbol (`--at-symbol`)
- Auto toolchain discovery with override controls
- Bootstrap and diagnostics commands (`--bootstrap`, `--doctor`)
- End-to-end smoke validation (`--self-test`)
- Re-patching support (chained hooks)

## Quick Start

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Check/prepare toolchains:

```bash
python bpatch.py --bootstrap
python bpatch.py --bootstrap --yes
python bpatch.py --doctor
```

Validate your setup end-to-end:

```bash
python bpatch.py --self-test
```

Patch using explicit address:

```bash
python bpatch.py <binary> --at <hex_address> --payload <payload.c> -o <output>
```

Patch using symbol lookup:

```bash
python bpatch.py <binary> --at-symbol <symbol_name> --payload <payload.c> -o <output>
```

## Toolchain Selection

Default behavior is to use whatever suitable compiler toolchain is already installed.

Optional controls:

- `--toolchain auto|gcc|clang`
- `--cc`, `--ld`, `--objcopy`
- `--target <triple>`
- `--payload-cflag` (repeatable)
- `--payload-ldflag` (repeatable)

Environment overrides:

- Global: `BPATCH_CC`, `BPATCH_LD`, `BPATCH_OBJCOPY`
- Preference: `BPATCH_TOOLCHAIN` (`auto`, `gcc`, `clang`)
- Target triple: `BPATCH_TARGET`
- Scoped: `BPATCH_ELF_X86_64_*`, `BPATCH_ELF_AARCH64_*`, `BPATCH_PE_X86_64_*`
- Extra flags: `BPATCH_PAYLOAD_CFLAGS`, `BPATCH_PAYLOAD_LDFLAGS`

## Repository Layout

- `bpatch.py` - main CLI and patching logic
- `bpatch_arch/` - architecture-specific backend logic
- `examples/` - ready-to-use payloads
- `docs/` - full documentation for beginners and advanced usage
- `include/` - runtime headers
- `targets/src/` - sample target source files
- `targets/bin/` - locally built sample binaries (gitignored)
- `tools/` - helper workflows/scripts

## Usage Scope

This project is for authorized analysis and research use.
See [docs/SECURITY_AND_ETHICS.md](docs/SECURITY_AND_ETHICS.md).
