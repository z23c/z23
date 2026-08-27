# Fleet release hardening

Copyright 2026 Rhett Creighton – Apache License 2.0

## Intent

Qualify one C23 release for four public nodes without weakening validation,
custody, or rollback boundaries. The release must recover an equal-height
competing-header fork through ordinary authenticated body download, refuse
ambiguous software-commons proofs and seals, and reject zero-value swap
contracts before persistence.

## Measured fleet condition

At `2026-08-27T08:04:14Z`, nodes 1, 2, and 4 independently reported verified
height 3,230,654. Node 3 reported height 3,230,421 while its peers advertised
height 3,230,654. Node 3 had accepted the canonical header sequence but lacked
the earliest body on the competing branch. Its existing recovery condition had
exhausted three attempts because it required the best header to be strictly
higher than the active tip and selected only the tip height.

The repaired scheduler permits an equal-height best-header branch, walks back
to the common ancestor, and queues the earliest missing body by the exact
best-chain hash. This changes download scheduling only. Header validity,
proof-of-work, chain-work selection, block validation, and activation remain
under their existing authorities.

## Release boundary repairs

- A root Merkle proof is canonical only when it is a directory proof with an
  empty path, zero levels, and zero children. The direct verifier and encoder
  now reject the same malformed root arena.
- Core sealing opens every repository-relative component with `O_NOFOLLOW`,
  hashes only regular files, and requires stable device, inode, size, mtime,
  and ctime before and after the read. Writer limits match reader limits.
  Duplicate or nonfinal roots, embedded NUL, truncated physical lines, and
  read failures are fatal parser errors.
- Positive swap amounts that convert below one zatoshi are refused. The output
  parameter remains untouched on every refusal, and all previously valid
  truncation and upper-bound behavior remains unchanged.
- Changes to the Merkle verifier now select `code_merkle_proof` in the native
  impact plan, preventing future focused gates from omitting its proof KAT.

## Evidence

Observed at `2026-08-27T08:48:07Z` (`2026-08-27T04:48:07-04:00`) on an AMD
Ryzen 7 PRO 8840U with GCC 16.1.1:

```text
release-focused exact set   PASS  35/35 groups; groups_failed=0; self_skips=0
core_seal exact             PASS  groups_failed=0; self_skips=0
impact_composition exact    PASS  groups_failed=0; self_skips=0
vault_read exact            PASS  groups_failed=0; self_skips=0
core-seal-check             PASS  70 files; 23 sections
core-seal-root-mirror       PASS
hotswap-module-imports      PASS  8 modules; no undeclared imports
file-size ceiling           PASS  39 application baselines unchanged
git diff --check            PASS
full lint                   PASS  156/157 before size repair
```

The one lint refusal was `swap_controller.c` growing from its 1,053-line
ratchet to 1,080 lines because of a test-only wrapper. The wrapper was removed,
the production converter remained directly tested, the file returned to 1,053
lines, and the exact size gate passed without raising a threshold.

## Remaining acceptance

The final committed source identity still requires the complete local release
suite, immutable candidate build, process qualification on each host, and
four-way verified-tip agreement. Node 4 requires copy-first protection before
its one-way schema migration. No wallet or canonical database surgery is part
of this procedure.
