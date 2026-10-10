<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Fast-object staging and Apple SDK cache closure

Fast-object admission uses anonymous Linux staging where creation and exact
descriptor publication are supported. It never overwrites a destination.
Unsupported anonymous creation can select the existing named staging path
before writes; permission, integrity and publication errors do not select a
fallback. An exact verified object with an absent sidecar can complete that
sidecar through normal admission. Divergent bytes, symlinks and a sidecar-only
entry remain refused.

The package verifier accepts narrow Apple SDK metadata spellings in its
preprocessor closure: exact standalone Swift unsafe-nonisolated metadata,
standalone Swift unavailable metadata with an unescaped printable ASCII
message, and dollar signs in assembly aliases. Mixed quoted attributes,
different Swift spellings, escapes and slash-containing aliases remain
ineligible. External assembly payloads remain ineligible.

## Source and observations

The Linux carrier source was qualified against
`ea69109cf4d7bd802b27d81efc6962995464c360`. Integration is re-anchored at
`024b4b95dfb967fa2353cfa22475c1412b011cb0`; the three affected preimages are
unchanged, but dependency changes require separate current-base acceptance.
Linux observation metadata retained at 2026-10-10T04:58:00Z identifies
GCC 14.2.0 (Ubuntu 14.2.0-4ubuntu2~24.04.1), Linux 6.8.0-142-generic and
an AMD Ryzen 9 7950X3D 16-Core Processor. These are functional and allocated
block observations from 2026-10-10, not a matched performance benchmark.
Combined source patch SHA256:
`58346868cc3bf03c29c5df5d7bbe0b8e03b6fdca079c7b62846c772c200f2d09`.

Linux tests reached actual admission and descriptor publication. Corrected
parent tests failed; candidate tests passed. Disabling anonymous staging and
disabling exact incomplete-pair recovery each failed their intended production
boundary assertions; restoring source passed. Process-death controls include
staging before publication and death after object publication, followed by an
exact retry and re-export. These are not power-loss durability tests.

In isolated Linux fixtures, prepublication named staging retained 4,096
allocated file bytes after process death; anonymous staging retained zero.
After publication, two hardlinked names and one name each accounted for the
same 4,096 unique-inode bytes. That difference is names, not saved object
blocks. Directory blocks increased from 4,096 to 12,288 in both cases.
Counts deduplicate device/inode identity and use allocated blocks times 512.
No fleet-wide disk saving is established. Portable named staging retains its
prepublication orphan-space limitation.

On an arm64 Apple M4 Mac16,10 with Apple Clang 17.0.0, the registered carrier
group passed on the narrow scanner. At 2026-10-10T05:20:12Z an instrumented
mutation batch began through installed admission. The old scanner produced
12 assertion failures, including both existing cold/warm compiler-count
checks. A forced-eligible scanner produced 11 failures, including an external
`.incbin` byte mutation causing reused output to differ from a fresh control.
Restoration passed: one group ran, zero failures, self-skips or unobserved
environment requirements; test wall time was 98.5 seconds. The final candidate
source hashes were verified unchanged.

| Mac phase log | SHA256 |
|---|---|
| Old scanner | `e3e7d4bb575fd27aed6359705b37893c77447712c6fa90c4560684b043e4b57a` |
| Forced eligible | `2be1846424ef6315050de352b4abe227dbeafacbbe468479d0f5eeb3cd4eff97` |
| Restored | `a0f0646971131ad4fa51eb8d7beae241165f4df0b0f473dd573a77eb9806dc7d` |

Each failing mutation received the canonical runner's single alone retry.
The runner deletes the first log when that retry also fails; retained final
logs establish the assertions, not the first-attempt cause. Complete phase
wall times, including preparation and retries, were 759.08, 279.85 and 178.48
seconds. Earlier owner-check refusals had no test verdict and remain separate
unresolved infrastructure observations. This is functional cache-closure and
bounded space evidence, not a matched latency benchmark, fleet transport
acceptance, or publication proof.

At integration base `024b4b95dfb967fa2353cfa22475c1412b011cb0`, canonical
`agent-verify ONLY=fastobj_carrier` passed all four gates: complexity, the
uncached exact registered group, capability inventory generation and
`lint-fast`. One group ran with zero failures, self-skips or unobserved
environment requirements; suite wall time was 112.2 seconds. The complete
verification log SHA256 is
`29649bb8a9a031b9ec454ec9583a9ebf395b59007a1a3e00b7db13ed89a91318`.
The qualified source postimages are carrier `a33be53f`, test `a5540ff9` and
verifier `845e4b30`; the combined patch above binds their complete bytes.
This focused acceptance is separate from exact-pair publication proof.

The exact-pair publication attempt
`e8938c3c67ea405ec709e0ad82467cb1cb6f2b4a` against
`7bcd688b84d181a7dff72fa048d60a34d30fe005` failed capability closure:
its new attribute parser reached the unclassified libc `ungetc` symbol.
The complete lint log SHA256 is
`27c5f11fbbff582fbaf6eaa31680af2bd4797d7caea21e456f865824c10649f1`.
The classification repair assigns `ungetc` to `CAP_FS_READ`: it pushes one
byte back into an existing input stream without writing external storage.
The verifier already declares this capability; no module authority or gate
threshold changes. The failed publication attempt remains failure evidence.
