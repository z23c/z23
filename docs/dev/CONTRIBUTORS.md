# Contributors

Z23 exists because people put real care into it. Authorship is
preserved in git history (PRs merge with merge commits — see the
[contributor graph](https://github.com/z23c/z23/graphs/contributors)
for the live picture); this file recognizes contributors in one place.

All contributions are licensed under Apache-2.0 (inbound = outbound) —
see [CONTRIBUTING.md](../../.github/CONTRIBUTING.md#licensing-of-contributions).

## Maintainer

- **Rhett Creighton** ([@RhettCreighton](https://github.com/RhettCreighton)) — project owner

## Contributors

- **[@CesareFI](https://github.com/CesareFI)** — release-only package verifier
  selection in shipped nodes, selection/refusal regression coverage, and the
  sealed-verifier A-B-A fixture portability fix (PR #62); the private
  per-pair observation store lifecycle for signed proof-runner observations
  (PR #63); the signed coverage manifest codec over those observations and
  its regression group (PR #64). With the Kimi agent (GPT-6): full-width
  `walletunlock` timeout rejection before narrowing, full-width SQLite type
  and range checks on the stage-repair cursor, and the refusal to report a
  future-started proof worker as executing (2026-10).

- **[@jmprcx](https://github.com/jmprcx)** — key-material hardening (AES
  state cleanse, base58/bech32 encode-side stack caps, PR #1); typed
  peer-offence DoS table, `getrawtransaction` FILE\*-cache removal +
  FD-leak fix, canonical flat-loader forward pass (PR #2). First
  external contributor.

*Added a contribution? Append yourself here in your PR, or we'll do it
for you in the merge.*
