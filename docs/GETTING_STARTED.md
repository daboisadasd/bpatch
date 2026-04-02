# Getting Started

This guide gets `bpatch` running on a fresh machine.

## 1. Install Python Requirements

```bash
pip install -r requirements.txt
```

## 2. Check/Install Toolchains

Dry-run bootstrap (shows what would be installed):

```bash
python bpatch.py --bootstrap
```

Execute bootstrap commands:

```bash
python bpatch.py --bootstrap --yes
```

Verify what `bpatch` can see:

```bash
python bpatch.py --doctor
```

## 3. Run Self-Test

```bash
python bpatch.py --self-test
```

Expected result:

- `Self-test passed`
- A marker file written by injected payload
- Baseline and patched target outputs match

If it fails, use [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## 4. See Available Example Payloads

```bash
python bpatch.py --list
```

## 5. First Real Patch

Using explicit address:

```bash
python bpatch.py <binary> --at 0x401234 --payload examples/dump_string.c -o <binary>.patched
```

Using symbol lookup (preferred when symbols exist):

```bash
python bpatch.py <binary> --at-symbol hook_me --payload examples/dump_string.c -o <binary>.patched
```

## 6. Recommended Defaults

By default, `bpatch` auto-selects installed toolchains.
Override only when needed.

Optional controls:

- `--toolchain auto|gcc|clang`
- `--cc`, `--ld`, `--objcopy`
- `--target <triple>`
- `--payload-cflag`, `--payload-ldflag`

Environment-based defaults:

- `BPATCH_TOOLCHAIN`
- `BPATCH_TARGET`
- `BPATCH_CC`, `BPATCH_LD`, `BPATCH_OBJCOPY`

## 7. What To Learn Next

- [REVERSE_ENGINEERING_PRIMER.md](REVERSE_ENGINEERING_PRIMER.md)
- [FIRST_PATCH_WALKTHROUGH.md](FIRST_PATCH_WALKTHROUGH.md)
- [CLI_REFERENCE.md](CLI_REFERENCE.md)
