# Start Here

This guide is for people who are new to reverse engineering and want to use `bpatch` safely and confidently.

## What bpatch Actually Does

`bpatch` modifies a binary so that when execution reaches a chosen address, it jumps into injected code.
Your payload runs, then the original program continues.

Think of it as "insert a tiny custom hook without source code access."

## Who This Is For

- Malware analysts and reverse engineers
- Security researchers instrumenting binaries
- Learners practicing binary patching techniques

If you are brand new, that is okay. Start with the Getting Started guide first.

## 20-Minute Learning Path

1. Install dependencies and run setup checks:
   - `python bpatch.py --bootstrap`
   - `python bpatch.py --doctor`
2. Validate end-to-end locally:
   - `python bpatch.py --self-test`
3. Learn concepts in [REVERSE_ENGINEERING_PRIMER.md](REVERSE_ENGINEERING_PRIMER.md)
4. Do the full beginner lab in [FIRST_PATCH_WALKTHROUGH.md](FIRST_PATCH_WALKTHROUGH.md)

## Mental Model (Simple)

- You choose a location (`--at` or `--at-symbol`)
- `bpatch` steals enough original instructions at that location
- `bpatch` writes an injected section with:
  - prologue (save context)
  - your payload
  - epilogue (restore context)
- Original site is replaced with a jump to injected section
- Execution returns to original flow afterward

## Recommended First Commands

```bash
python bpatch.py --doctor
python bpatch.py --self-test
python bpatch.py --list
```

## Safety Rules

- Only patch binaries you are legally authorized to analyze.
- Keep originals unchanged and write to a new output path.
- Verify behavior using controlled test targets before touching real samples.
- Track each patch with notes (input hash, output hash, location, payload).

## Next Docs

- Setup: [GETTING_STARTED.md](GETTING_STARTED.md)
- RE basics: [REVERSE_ENGINEERING_PRIMER.md](REVERSE_ENGINEERING_PRIMER.md)
- First lab: [FIRST_PATCH_WALKTHROUGH.md](FIRST_PATCH_WALKTHROUGH.md)
- Troubleshooting: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
