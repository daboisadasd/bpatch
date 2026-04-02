# Troubleshooting

Use this page when commands fail or patched binaries behave unexpectedly.

## First-Line Diagnostics

Run these first:

```bash
python bpatch.py --doctor
python bpatch.py --self-test
```

If `--self-test` fails, fix environment/toolchains before patching real targets.

## Error: No Usable Payload Toolchains

Symptom:

- `Could not find ... toolchain`

Fix:

1. `python bpatch.py --bootstrap`
2. `python bpatch.py --bootstrap --yes`
3. Re-open terminal (PATH refresh)
4. `python bpatch.py --doctor`

If needed, pin tools with `--cc`, `--ld`, `--objcopy`.

## Error: Symbol Not Found (`--at-symbol`)

Symptom:

- `Symbol not found`
- `Could not find nm/llvm-nm`

Fix:

- Ensure symbol exists (`nm <binary>`)
- Use unstripped build when possible
- Install `nm`/`llvm-nm`
- Fall back to explicit `--at`

## Error: Payload Compilation Failed

Common causes:

- Toolchain mismatch for target format/arch
- Unsupported flags
- Payload code using unavailable runtime APIs

Fix:

- Try `--toolchain gcc` or `--toolchain clang`
- Explicitly set `--target`
- Remove extra flags and reintroduce gradually
- Start from `examples/` payloads

## Error: Link Failed

Common causes:

- Wrong linker for chosen compiler
- Missing linker binary
- Incompatible extra linker flags

Fix:

- Let auto mode choose linker first
- Remove `--ld` override and retry
- If needed, force compiler-driver linking by leaving `--ld` unset

## Patched Binary Crashes

Checklist:

- Validate baseline binary runs first
- Confirm hook location is correct
- Confirm ABI assumptions match target platform
- Use minimal payload first (log only)
- Re-check with `--self-test`

## Behavior Changed Unexpectedly

- Verify output from unpatched vs patched binaries
- Confirm payload only does intended side effects
- Confirm you are patching intended function/site

## Still Stuck?

Capture and share:

- full command
- full stderr/stdout
- `python bpatch.py --doctor` output
- host OS + architecture
- binary format/arch
