# First Patch Walkthrough

This walkthrough is for first-time users.
It shows a complete patch cycle from symbol lookup to behavior validation.

## Goal

Patch a sample binary so your payload writes a marker/log, while normal program behavior remains intact.

## Prerequisites

- `python bpatch.py --doctor` shows at least one usable toolchain
- `python bpatch.py --self-test` passes

## Step 1: Build Sample Target (Windows example)

```bash
gcc -O2 -fno-stack-protector targets/src/stress_target.c -o targets/bin/stress_target.exe
```

## Step 2: Resolve Hook Symbol

Use symbol-based patching so you do not manually manage addresses:

```bash
python bpatch.py targets/bin/stress_target.exe --at-symbol encrypt_block --payload examples/stress_payload_win.c -o targets/bin/stress_patched.exe
```

What happens here:

- `--at-symbol encrypt_block` resolves symbol VA via `nm`
- Payload is compiled and injected
- Target site is patched to jump to injected section

## Step 3: Run Unpatched and Patched Binaries

Run unpatched:

```bash
targets/bin/stress_target.exe
```

Run patched:

```bash
targets/bin/stress_patched.exe
```

Expected:

- No crash
- Same pass/checksum semantics as baseline
- Payload side effects (log/marker file) appear

For stress-specific expected outputs, see [STRESS_TEST.md](STRESS_TEST.md).

## Step 4: Inspect Payload Effects

Check output artifact(s), for example:

```bash
type C:\bpatch_stress.txt
```

## Step 5: Iterate Safely

- Change one payload behavior at a time
- Re-run baseline vs patched comparisons
- Keep each patch output in a separate file

## Useful Variations

Explicit-address mode:

```bash
python bpatch.py targets/bin/stress_target.exe --at 0x140001500 --payload examples/stress_payload_win.c -o targets/bin/stress_patched.exe
```

Toolchain preference mode:

```bash
python bpatch.py targets/bin/stress_target.exe --at-symbol encrypt_block --payload examples/stress_payload_win.c --toolchain clang -o targets/bin/stress_patched.exe
```

## Common Newbie Mistakes

- Trying to use stripped binaries with `--at-symbol`
- Forgetting to verify baseline output before patching
- Assuming all crashes are patching bugs (often toolchain mismatch)

If anything fails, jump to [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
