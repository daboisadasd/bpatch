# FAQ

## Is this a runtime injector?

No. `bpatch` is a static patching tool. It modifies binary files on disk.

## Should I use `--at` or `--at-symbol`?

Use `--at-symbol` when symbols are available. It is usually more stable and readable.
Use `--at` when symbols are stripped.

## Why does `--at-symbol` fail on some binaries?

Likely causes:

- symbols are stripped
- no matching `nm` tool is installed
- symbol name differs from expected

## Can I patch without specifying compiler tools?

Yes. Default mode auto-detects available toolchains.
Only specify overrides if auto selection is not what you want.

## Does bpatch overwrite my original binary?

Not unless you explicitly set output to the same path (which is blocked by safety checks).
Use `-o` for patched output.

## What is a safe first payload?

A payload that only logs or dumps arguments without modifying control flow/returns.

## Can I patch already-patched binaries?

Yes, re-patching/chaining is supported.
Still validate behavior after each patch iteration.

## Is this suitable for production binaries?

Use with extreme caution. Always test in isolated environments first.

## Does this support ARM32, x86 32-bit, or PE ARM64?

Not yet. Current support is ELF x86_64/aarch64 and PE x86_64.

## Where do I start if I am new to RE?

Start with:

1. [START_HERE.md](START_HERE.md)
2. [GETTING_STARTED.md](GETTING_STARTED.md)
3. [REVERSE_ENGINEERING_PRIMER.md](REVERSE_ENGINEERING_PRIMER.md)
4. [FIRST_PATCH_WALKTHROUGH.md](FIRST_PATCH_WALKTHROUGH.md)
