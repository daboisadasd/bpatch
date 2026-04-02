# Reverse Engineering Primer (For bpatch Users)

This is a practical primer focused on the concepts you need to patch binaries with confidence.

## Core Terms

- Binary: compiled executable code (`.exe`, ELF).
- Address / VA: virtual address where code executes.
- RVA: PE relative virtual address (VA minus image base).
- Symbol: named function/object in symbol tables.
- Callsite / hook site: location where you redirect execution.
- Trampoline: injected bridge that runs payload then returns.
- ABI: calling convention and register/stack rules.

## Binary Formats in bpatch

- ELF (Linux/Android)
  - `x86_64`
  - `aarch64`
- PE (Windows)
  - `x86_64`

`bpatch` auto-detects format and architecture.

## Why Register/ABI Knowledge Matters

Your payload runs inside another program.
If ABI assumptions are wrong, behavior can corrupt or crash.

Common argument macros exposed by runtime headers:

- Linux x86_64: `ARG1=rdi`, `ARG2=rsi`, ...
- Linux aarch64: `ARG1=x0`, `ARG2=x1`, ...
- Windows x64: `ARG1=rcx`, `ARG2=rdx`, ...

## Choosing a Hook Location

Good hook points are:

- Stable function entries
- Branches that always execute in your scenario
- Areas with enough instructions to steal safely

Avoid:

- Highly timing-sensitive code (unless you know impact)
- Anti-debug paths you have not modeled
- Locations with ambiguous control flow or self-modifying behavior

## Address vs Symbol

Use `--at-symbol` when symbols exist.

Benefits:

- Less fragile across recompiles than hardcoded addresses
- Better readability and reproducibility

Use `--at` when symbols are stripped or unavailable.

## How to Find Targets in Practice

Tool examples:

- Ghidra / IDA: inspect functions and addresses
- x64dbg / WinDbg: runtime verification
- `nm` / `llvm-nm`: symbol lookup

Workflow:

1. Identify candidate function/branch
2. Validate hit frequency and side effects
3. Patch with minimal payload first (log or dump)
4. Compare original vs patched behavior

## Payload Design Tips

Start small and deterministic.

Good first payloads:

- log register values
- dump string/buffer argument
- write a marker file

Then iterate to advanced logic only after baseline is stable.

## Validation Mindset

Always compare unpatched and patched output.

- same functional output (unless intentionally modified)
- no crashes/hangs
- expected side-effect artifact from payload

Use `--self-test` to validate your local environment before live targets.

## Legal and Safety Reminder

Patch only authorized binaries.
Use isolated test environments.
Do not deploy modified binaries to production systems without explicit approval.
