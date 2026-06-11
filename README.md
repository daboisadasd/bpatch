# bpatch

Static binary instrumentation for malware analysis and reverse engineering.

bpatch injects a C payload into an existing binary without source code.
At the patch site, execution jumps to the injected section, your payload runs
with full access to all CPU registers, then original execution resumes.
No OS hooks, no DLL injection, no debug API — the patch is entirely inside
the binary on disk.

**Supported targets**

| Format | Architecture | Platform |
|--------|-------------|----------|
| ELF    | x86_64      | Linux, Android |
| ELF    | aarch64     | Linux, Android |
| PE     | x86_64      | Windows |
| PE     | aarch64     | Windows on ARM |

---

## Installation

Requires Python 3.11+ and a C toolchain (clang or gcc).

```
pip install -e .
```

Check what toolchains were found and whether everything is wired up:

```
python -m bpatch --doctor
python -m bpatch --bootstrap      # show install commands
python -m bpatch --bootstrap --yes # run them
python -m bpatch --self-test       # compile + inject + run a local sanity check
```

---

## Quick start

Patch at an explicit virtual address:

```
python -m bpatch target.elf  --at 0x401234    --payload examples/trace_args.c
python -m bpatch target.exe  --at 0x140001234 --payload examples/trace_args_win.c
```

Patch by symbol name (binary must have debug symbols):

```
python -m bpatch target.elf  --at-symbol hook_me   --payload examples/hexdump_arg.c
python -m bpatch target.dll  --at-symbol CreateFile --payload examples/trace_args_win.c
```

Patch by PE export name (works on stripped DLLs):

```
python -m bpatch target.exe --at-export CreateFileW  --payload examples/trace_args_win.c
python -m bpatch target.dll --at-export DllGetVersion --payload examples/log_regs_win.c
```

Patch by byte pattern (most powerful — works on packed/stripped binaries):

```
python -m bpatch target.exe --at-pattern "48 89 5C 24 ?? 57 48 83 EC 20" \
    --payload examples/trace_args_win.c

# Pattern found at 3 sites — hook the second one:
python -m bpatch target.exe --at-pattern "55 48 89 E5 ?? ?? ?? ??" \
    --at-pattern-nth 2 --payload examples/hexdump_arg_win.c
```

Patch by RVA (address without imagebase):

```
python -m bpatch target.exe --at-rva 0x16c0 --payload examples/log_regs_win.c
```

---

## Revert a patch

Every injection embeds a 32-byte undo header in the `.inj` section.
To restore the original binary:

```
python -m bpatch target.exe --undo -o target_clean.exe
```

---

## Multi-site injection

Inject multiple payloads in one command using a JSON spec:

```json
[
  {
    "at_export": "CreateFileW",
    "payload": "examples/trace_args_win.c",
    "comment": "log filenames opened"
  },
  {
    "at_export": "RegOpenKeyExW",
    "payload": "examples/trace_args_win.c",
    "comment": "log registry reads"
  },
  {
    "at_pattern": "FF 15 ?? ?? ?? ?? 85 C0 74",
    "payload": "examples/force_return_0_win.c",
    "comment": "bypass licence check"
  }
]
```

```
python -m bpatch malware.exe --sites sites.json -o malware_instrumented.exe
```

Sites are applied sequentially; each writes an intermediate binary that
the next site reads. Any address format (`at`, `at_rva`, `at_symbol`,
`at_export`, `at_pattern`, `at_pattern_nth`) works inside the JSON.

---

## Hook chaining

Re-inject a site that was already patched:

```
python -m bpatch target.exe --at 0x140001234 --payload second_hook.c --chain
```

Without `--chain`, bpatch warns you when the site already begins with a JMP.
With `--chain`, it injects anyway — the new payload runs before the old one
because the trampoline it installs executes the old JMP as a stolen instruction.

---

## Example payloads

All payloads live in `examples/`. Linux and Windows variants exist for each.

| Payload | What it does |
|---------|-------------|
| `trace_args.c` / `_win.c` | Log all argument registers per call |
| `hexdump_arg.c` / `_win.c` | Hex+ASCII dump of the buffer at ARG1 |
| `dump_string.c` / `_win.c` | Dump a null-terminated string from ARG1 |
| `dump_bytes_win.c` | Dump a length-prefixed buffer (ARG1=ptr, ARG2=len) |
| `count_hits.c` / `_win.c` | Running call counter stored in the payload section |
| `force_return_0.c` / `_win.c` | Override return value to 0 (bypass checks) |
| `patch_retval_win.c` | Log and override a function's return value |
| `log_regs_win.c` | Log all 16 GP registers on each hit |
| `network_log_win.c` | Capture send() buffer content (C2 traffic) |

Show the full list with descriptions:

```
python -m bpatch --list
```

Write the runtime header to the current directory for payload development:

```
python -m bpatch --dump-header                   # Linux x86_64
python -m bpatch --dump-header --arch aarch64    # Linux aarch64
python -m bpatch --dump-header --pe              # Windows x64
python -m bpatch --dump-header --pe --arch aarch64  # Windows ARM64
```

---

## Writing a payload

A payload is a plain C file. The only required function is `payload()`.

```c
#include "bpatch_rt.h"

void payload(void) {
    // ARG1..ARG6 are the function arguments (rdi/rsi/... on Linux x64)
    // RETVAL is rax / x0 — write to it to override the return value
    char path[] = "/tmp/out.txt";
    LOG_REG("arg1", ARG1, path);
    LOG_REG("arg2", ARG2, path);
}
```

bpatch rewrites `void payload()` to `void payload(ctx_t *ctx)` and injects
`ctx` automatically. Registers are saved before your payload runs and restored
after — writing to `ctx->rax` (or `RETVAL`) takes effect when execution resumes.

**Rules:**
- No libc, no includes except `bpatch_rt.h`
- No PLT/GOT calls — all helpers must be inlined (the runtime header handles this)
- Use `char arr[] = "..."` for string literals, not `char *p = "..."` (the latter
  references `.rodata` outside the injected section and will crash)
- The payload is compiled with `-ffreestanding -fno-builtin -fno-stack-protector`

---

## Compiler flags

```
--payload-opt O0|O1|O2|O3|Os|Oz   optimisation level (default O2)
--lto                              link-time optimisation; smaller payloads (clang+lld)
--payload-debug                    include debug symbols and force O0
--payload-sections                 -ffunction-sections + --gc-sections (dead code removal)
--payload-cflag FLAG               extra C compiler flag (repeatable)
--payload-ldflag FLAG              extra linker flag (repeatable)
```

---

## Toolchain reference

bpatch auto-discovers available toolchains.
Override with flags or environment variables when needed.

**Flags**

```
--toolchain auto|gcc|clang    prefer a compiler family (default: auto, tries clang first)
--cc COMPILER                 explicit compiler binary
--ld LINKER                   explicit linker binary
--objcopy OBJCOPY             explicit objcopy binary
--target TRIPLE               compiler target triple (e.g. aarch64-linux-gnu)
```

**Environment variables**

```
BPATCH_TOOLCHAIN      auto | gcc | clang
BPATCH_CC             explicit compiler path
BPATCH_LD             explicit linker path
BPATCH_OBJCOPY        explicit objcopy path
BPATCH_TARGET         target triple
BPATCH_PAYLOAD_CFLAGS   extra C flags (space-separated)
BPATCH_PAYLOAD_LDFLAGS  extra linker flags (space-separated)
```

Scoped overrides (take priority over global ones):

```
BPATCH_ELF_X86_64_CC
BPATCH_ELF_AARCH64_CC
BPATCH_PE_X86_64_CC
BPATCH_PE_AARCH64_CC
```

---

## Other options

```
--dry-run        show injection layout without writing the output binary
--chain          re-hook a site that already begins with a JMP
--undo           revert all bpatch injections using embedded undo headers
-o OUTPUT        output path (default: <binary>.patched[.exe])
-q / --quiet     suppress informational lines; show only results and errors
--version        print version and exit
```

---

## Repository layout

```
bpatch/            Python package — CLI, compiler, injector, pattern search, undo
bpatch_arch/       Architecture backends (x86_64, aarch64) — trampoline assembly
examples/          Ready-to-use payload C files
docs/              Extended documentation and walkthroughs
tests/             pytest unit and integration test suite
bpatch.py          Thin shim: "python bpatch.py" also works
pyproject.toml     Package metadata and test configuration
```

---

## Usage scope

This project is for authorized analysis and research use only.
See [docs/SECURITY_AND_ETHICS.md](docs/SECURITY_AND_ETHICS.md).
