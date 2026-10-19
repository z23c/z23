<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Shielded replay branch on Ledger Blue

## Question

Can a user see which consensus branch the Blue used for a read-only Sapling
ZIP-243 digest, without mistaking a known branch for an active chain tip?

## Experiment

The v7 shielded reviewer previously erased replay state after six matching
passes and showed only the digest. The digest changed with the requested
branch, but the final Blue page did not name that branch. A consensus Sapling
fixture test failed when it expected `ZIP243 BRANCH 0x76B809BB` and
`CHAIN UNCHECKED; NO SIGNING` on the digest page.

The reviewer now retains the branch accepted at BEGIN, displays it beside
the full digest, and clears it with the rest of the review on abort or USB
reset. An alternate known branch, `0x930B540D`, produces a distinct digest
and its own branch label. The branch policy checks that the ID is known; it
does not verify the active branch at a verified height. No signing command is
available in this app.

The screen simulator rendered 123 PNG pages for the two fixture wires and
the alternate branch. It checked 320 × 480 dimensions for every page and
decoded RGB SHA-256 values for the consensus summary, dark summary,
large-text summary, digest, dark digest, and both large-text branch pages.
The standard, dark, and large-text digest pages were visually inspected;
the branch label and warning fit without clipping.

## Results

Clang 22.1.6, AMD Ryzen 7 PRO 8840U, 2026-09-29T02:51:19-04:00
(2026-09-29T06:51:19+00:00):

| Check | Result |
| --- | ---: |
| Release tests | 60/60 passed |
| Sanitized Debug tests | 60/60 passed |
| `.text` | 33,280 bytes |
| `.data` | 0 bytes |
| `.bss`, including reserved stack | 4,320 bytes |
| Largest modeled stack path | 840 bytes |
| Stack budget and required margin | 1,536 bytes and 512 bytes |
| `.text` SHA-256, two clean pinned-SDK builds | `542f9d5e95e1160c56ddcb45207f31a9381f54d14d0dc2daa2e331a60e54a728` |
| Intel HEX SHA-256, two clean pinned-SDK builds | `e6f7b4a90063342d41d9807c2339a6432257c361e17638d581a8e90e74ac92c2` |
| Consensus digest RGB SHA-256 | `39a73bf57e30ffa833289e24a8726e586de864175f5d622578ce081b66245f29` |
| Consensus dark digest RGB SHA-256 | `f551ef8c2fbb6b87ea920a87ab8a872a1f5070b0455c06ef504f4ce3f55ace8a` |
| Consensus large-text branch RGB SHA-256 | `6b41bf2b5370876da0657f1099c6a9f4d3ce6060398f97d1bbd0baa41d360691` |

The Blue stack model excludes BOLOS frames. This image has not been
installed on a physical device. The public summary still cannot reveal
shielded recipients, amounts, or memos; this test establishes only digest
and branch display for a read-only review.
