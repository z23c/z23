# Main integration security repair

Copyright 2026 Rhett Creighton – Apache License 2.0

## Intent

Keep the fleet release fail closed after integrating concurrent `main` work.
The review tested three boundaries: length-delimited form input must not turn
ambiguous bytes into a money confirmation, rendered operator commands must
remain copyable at narrow terminal widths, and durable publications must not
leave stale or internally inconsistent state.

## Changes

- The shared form scanner accepts only ampersand-delimited fields and rejects
  raw or decoded NUL, malformed percent escapes, duplicate names, empty
  values, and destination overflow. Percent decoding reuses the canonical
  length-delimited nibble helper from `base/hex.h`.
- Narrow command output uses shell continuations and preserves every command
  byte. Package-host-only state recommends the idempotent `z23 join` command
  instead of assuming that a restart will enable a build worker.
- Segment publication and manifest rebuild share one process-wide publication
  lock. Broker status and custody documents use unique exclusive staging,
  complete writes, file and directory synchronization, and stale-document
  retirement on failure. Contradiction-freeze fields commit in one node DB
  transaction.
- The Sprout Groth16 KAT installs the embedded verification-key set before
  exercising contextual proof verification, matching the runtime readiness
  invariant without modifying consensus behavior.
- DHT expiry collection now applies the same live-row predicate to sequence,
  conflict, duplicate, and capacity decisions that a restart applies while
  loading the store. The periodic collector marks the complete persistence
  dirty state when it removes a row.
- The onion bridge acceptance waits for the dial lifecycle to finish after
  observing the bridge-closed counter. The production path deliberately
  records that counter before joining the pump threads and publishing the
  final inactive snapshot; the test no longer treats that valid interval as
  a teardown failure.
- Hot-swap package runs use private scratch directories and prove that the
  immutable object supplying `source_tu` and leaves re-links byte-identically
  to the artifact being receipted. The seal-root generator validates every
  character of the 64-digit lowercase hexadecimal root. Documentation now
  states that a post-`dlopen` consensus pin prevents stale leaf publication,
  not ELF constructor execution.
- Remote activation queues systemd restart without waiting for `Type=notify`.
  The existing progress-aware observer now starts immediately, so a slow disk
  can reach the explicit SLOW verdict instead of blocking before observation.
- Slow-host shutdown gives the derived flat-index/projection binding 120
  seconds. A live rotating-disk shutdown spent 18 seconds writing the flat
  file, crossed the former 20-second stage ceiling before binding, and forced
  the next boot into a full 3,233,145-row projection scan. The wider
  best-effort budget does not delay a completed stage.
- DHT request replay admission is transactional across local backpressure.
  Egress and replacement-probe saturation restore the exact displaced replay
  row and carry zero peer-offence weight; local record capacity is no longer
  misreported as peer flooding or identity failure.
- Snapshot proof-of-work challenges use only requester-visible, explicitly
  little-endian fields. Swarm provider offers retain signed expiry and are
  removed before scheduling, and rendered datadirs are POSIX-shell quoted.
- Hot-swap admission seals no more than 32 MiB before parsing, requires an
  exact unique ABI and core seal, refuses all pre-map callbacks and ambiguous
  ELF singleton tags, validates dynamic pointers against section metadata,
  and checks every undefined symbol against the resident import contract
  before `dlopen`. Every module producer omits runtime startup files.
- macOS descriptor-bound binary launch fails closed with `ENOTSUP`. The
  platform has no `fexecve`; reconstructing a pathname with `F_GETPATH` would
  reopen a replacement race between identity validation and execution.

## Evidence

Observed at `2026-08-26T22:57:37Z` (`2026-08-26T18:57:37-04:00`) on an
AMD Ryzen 7 PRO 8840U with GCC 16.1.1:

```text
test_sprout_groth16_kat      PASS  self_skips=0
test_sprout_phgr13_kat       PASS  self_skips=0
ONLY=store                   PASS  groups_failed=0; two pre-existing gated e2e skips
test_yardsale_app            PASS  self_skips=0
test_cli_render              PASS  self_skips=0
test_zcode_package_dev       PASS  self_skips=0
test_zcode_dev_objects       PASS  self_skips=0
test_qr                      PASS  self_skips=0
test_chain_segment           PASS  self_skips=0
test_chain_evidence_controller PASS self_skips=0
test_metaverse_agent_broker  PASS  self_skips=0
test_zcode_dht_record        PASS  self_skips=0
test_zcode_dht_service       PASS  self_skips=0
test_onion_bridge            PASS  self_skips=0; strict profile, two runs
hotswap package verify       PASS  two concurrent processes
hotswap artifact substitution REFUSED before receipt
core seal root selftest      PASS
ship remote transaction     PASS
check-hex-codec-single       PASS
test_shutdown_stagewatch     PASS  self_skips=0
test_block_index_topup       PASS  self_skips=0
test_net                     PASS  self_skips=0
test_zcode_package_dev       PASS  self_skips=0
test_zcode_swarm             PASS  self_skips=0
zcode_dht_service            PASS  self_skips=0
zcode_dht_frame_auth         PASS  self_skips=0
hotswap_module_v2            PASS  self_skips=0
real hotswap module          ADMITTED, MOUNTABLE; 47 imports resolved
ship selftest + transaction  PASS
lint-fast                    PASS
git diff --check             PASS
```

At `2026-08-27T03:14:20Z` (`2026-08-26T23:14:20-04:00`), the five groups
that failed only in the loaded pre-push run were repeated uncached on the
same host. All five passed: `test_crypto_registry`, `test_dev_platform`, and
lint-gate shards 03, 06, and 07. The crypto benchmark still records elapsed
time, but its correctness verdict now requires exact successful operation
counts instead of comparing scheduler-sensitive wall-clock intervals. The
file-size gate passed at the existing engine/application/config baseline and the
existing 22/22 library drift ratchet; neither acceptance threshold changed.
The following pre-push shell phase caught a whitespace-only drift in sealed
`connect_block.c` before publication. Restoring its exact manifest bytes made
the 70-file core seal pass; equivalent unsealed P2P formatting cleanup kept
the 22/22 ratchet unchanged. `test_msg_handlers`, `test_net`, and lint-gate
shards 06 and 07 then passed uncached with zero skips.
The push mapper also refused the changed crypto test until it had an explicit
impact owner. The new narrow rule resolves it to `test_crypto_registry`, the
shared `crypto` group, and lint contracts; the impact-rule checker, selector
test, crypto group, and lint shard 03 all passed uncached.

The next `origin/main` introduced automatic provider-record discovery for
stalled swarm downloads and proposed raising the file-size drift ratchet from
22 to 29. Integration retained the already-proven 22 limit. The discovery
bridge was adapted to the current swarm admission API by carrying each signed
provider record's exact expiry into `peer_offer`; no synthetic lifetime is
minted. `test_zcode_swarm_dht`, `test_zcode_swarm`, `test_zcode_dht_service`,
`test_crypto_registry`, and lint shard 03 passed uncached with zero skips.
The 255-group pre-push intersection then passed 254 groups and exposed one
deterministic operator-message regression in `test_ratify_mint_anchor`: the
refusal remained fail-closed but labeled its applied frontier only as `h=`.
The message now names `applied=` explicitly; the exact group passed uncached.
The next complete intersection passed all 255 functional groups but refused
authority for three self-skips. Formatting-only changes in the simulation
family were restored byte-for-byte so the known-open chaos experiment is no
longer falsely selected; the same size reduction moved into already-affected
hot-swap, broker, and CLI units. Their three exact groups passed uncached, and
the file-size ratchet remained 22/22.

At `2026-08-27T02:07:25Z` on `rhett3.dev`, the clean shutdown began saving
3,233,145 flat-index entries. The save completed at `02:07:43Z`; the
`fast-restart-persist` 20-second watchdog fired before the projection binding
was written. The following boot reported monotonically increasing
`block_index.projection_topup` progress from zero, directly demonstrating the
avoidable cold-start cost.

The Yardsale acceptance specifically proved that `?confirm=true`,
`confirm=true anything`, `confirm=true%00false`, and a malformed percent
escape cannot arm or broadcast a purchase. The CLI acceptance reconstructed
both commands byte-for-byte at width 40, including a long unbroken datadir
token.

The DHT acceptance proved identical admission and digest results before and
after restart-equivalent collection. Its service test retained a row that
expired inside the 300-second debounce interval, then removed it exactly at
the boundary and observed the dirty flag, generation, and persistence timer.

At `2026-08-27T04:44:18Z`, integration review refused three experimental
surfaces from the release: hot-swap shelf retirement could unload the module
named by the active registry under concurrent publication; Merkle inclusion
proofs accepted ambiguous overlong paths and malformed direct-verifier child
arenas; sectional sealing did not yet match the code-index path and stable-file
rules. Their commits remain visible in history, but the release tree restores
the prior reviewed implementations and does not register those features.
Deleted-path impact rules keep their surviving security groups selected.

The retained DHT bridge now compares provider-record expiry against Unix wall
time, not monotonic uptime. An already-expired route remained unadvertised in
the production application boundary test. The combined uncached acceptance
ran `zcode_dht_service`, `zcode_swarm_dht`, `zcode_swarm`, `code_merkle`,
`hotswap_module_v2`, `hotswap_loader`, and `dev_platform`: 7/7 passed with
zero skips. The ship transaction, 972-group documentation count, 70-file
consensus seal, and hot-swap root mirror also passed. Slow local deployment
exit 3 now reports only `UNVERIFIED`; it preserves matching worker bytes but
does not claim progress that was not observed.

The first full ship lint then refused four integration regressions before any
host received bytes. Snapshot serving now uses the canonical little-endian
codec; immutable SQLite preflight resolves its open descriptor through the
platform path API; the ASan ADX contract checks the host-selected LTO flag;
and ten source files now state precise public purposes. Their four exact lint
gates passed together. The network fixed-byte challenge KAT and the immutable
database migration group also passed uncached with zero skips.

## Remaining acceptance

The repository's full lint gate set passed; `make lint` prints what it ran,
and the canonical list lives in the LINT-GATES block of
docs/DEFENSIVE_CODING.md. The first full release suite ran every registered
group bar the gated ones and exposed the strict-profile onion test race; the
corrected test passed twice without cache. The exact committed tree still
requires a complete release ship gate. Fleet health is established only after
the running processes report the same shipped source identity and retain P2P
synchronization.
