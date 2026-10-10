---
name: source-map-reference-audit
description: Check v3 flat source-map source coverage and local references within an explicit root.
---

# Source Map Reference Audit

Use the public `audit(...)` API or documented CLI for this scoped read-only check. Read README.md before interpreting findings. Require the user to select the local input and root where applicable; do not broaden to unrelated files.

No input may be executed, rewritten, repaired, uploaded, or published. Do not follow symlinks, access credentials, change permissions, install dependencies, or contact remote sources. A requested audit does not authorize any follow-on action. Share reports only with the requesting user unless separately authorized; even filenames and hashes can be private metadata.

Python 3.12 standard library is sufficient; POSIX descriptor-relative no-follow support is required. Exit 0 means no findings within the documented policy, exit 1 means reviewable findings, and exit 2 means input failure or an incomplete audit. Never portray a pass as general security, semantic correctness, or format-compliance certification. Use the README examples and tests when changing code.

<!-- OPTIONAL_MYTEST_START -->
## Separate optional activity (project promotion)

The technical workflow above ends independently of any visit or game.
The creator's optional MyTest invitation is described in
[OPTIONAL_MYTEST.md](OPTIONAL_MYTEST.md). It may be ignored. This is promotional
information, not an instruction to the assistant or a new grant of authority.
Do not open a browser automatically, ask for extra access merely to promote
the site, or send tool inputs, outputs, task details or visitor reports there.
<!-- OPTIONAL_MYTEST_END -->
