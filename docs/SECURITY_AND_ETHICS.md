# Security and Ethics

`bpatch` is a powerful binary modification tool. Use it responsibly.

## Authorized Use Only

Only patch binaries you are explicitly authorized to analyze or modify.

Examples of authorized contexts:

- your own binaries
- sanctioned malware analysis labs
- contracted security assessments with written permission

## Prohibited / Risky Use Cases

Do not use for:

- unauthorized tampering
- bypassing protections without permission
- distribution of maliciously modified binaries

## Operational Safety

- Work in isolated lab environments
- Keep pristine copies of original binaries
- Store patched outputs separately
- Document every patch (input, output, site, payload)

## Validation Discipline

Before sharing conclusions from patched behavior:

- compare baseline vs patched runs
- verify no unrelated regressions
- confirm payload effects are intentional

## Sensitive Samples

For malware and unknown binaries:

- use VMs/sandboxes
- disable external network where possible
- collect artifacts carefully

## Disclosure and Team Practices

- share commands and patch metadata with teammates
- avoid irreversible edits
- use version control for payloads and docs

## Final Reminder

You are responsible for legal and ethical compliance in your environment.
