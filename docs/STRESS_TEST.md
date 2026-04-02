# BPATCH Stress Test

## Build the target

Requires MinGW `gcc` in `PATH`.

```bash
gcc -O2 -fno-stack-protector targets/src/stress_target.c -o targets/bin/stress_target.exe
```

## Find the injection address

```bash
nm targets/bin/stress_target.exe | findstr encrypt_block
```

It will look like:

```text
0000000140001500 T encrypt_block
```

## Run baseline (unpatched)

```bash
targets/bin/stress_target.exe
```

Expected output includes:

```text
[stress] PASS -- all threads completed, no corruption detected
[stress] combined checksum: 0xXXXXXXXX
```

Record the checksum. The patched binary must produce the exact same value.

## Inject the stress payload

```bash
python bpatch.py targets/bin/stress_target.exe --at 0x140001500 --payload examples/stress_payload_win.c -o targets/bin/stress_patched.exe
```

## Run patched binary

```bash
targets/bin/stress_patched.exe
```

Expected results:

1. Same PASS message and same combined checksum as unpatched
2. `C:\bpatch_stress.txt` exists with roughly 40 log entries

Check the log:

```bash
type C:\bpatch_stress.txt
```

## What this test covers

- All 4 Win64 argument registers (`rcx/rdx/r8/r9`) read correctly
- Callee-saved registers (`rbx`, `r12-r15`) not corrupted across 8000 calls
- XMM floating point registers not corrupted
- 4 threads all hitting the same injection point simultaneously
- PEB walking under thread contention (`CreateFileA` resolved 40 times)
- Stack integrity maintained across 6 call levels deep
- O2-optimized target (non-standard prologue: `push rbx`, not `push rbp`)
- Static variable in `.inj` section used as call counter across all threads

If the checksum changes or the binary crashes, something is broken.
