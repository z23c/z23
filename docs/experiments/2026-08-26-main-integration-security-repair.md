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
check-hex-codec-single       PASS
git diff --check             PASS
```

The Yardsale acceptance specifically proved that `?confirm=true`,
`confirm=true anything`, `confirm=true%00false`, and a malformed percent
escape cannot arm or broadcast a purchase. The CLI acceptance reconstructed
both commands byte-for-byte at width 40, including a long unbroken datadir
token.

The DHT acceptance proved identical admission and digest results before and
after restart-equivalent collection. Its service test retained a row that
expired inside the 300-second debounce interval, then removed it exactly at
the boundary and observed the dirty flag, generation, and persistence timer.

## Remaining acceptance

The repository's 154 lint gates passed. The first full release suite ran 961
of 970 registered groups and exposed the strict-profile onion test race; the
corrected test passed twice without cache. The exact committed tree still
requires a complete release ship gate. Fleet health is established only after
the running processes report the same shipped source identity and retain P2P
synchronization.
