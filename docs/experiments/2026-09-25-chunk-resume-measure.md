<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Verified chunk reuse after interrupted transfer

Date: 2026-09-25T03:03:39Z. Source commit:
`2f2ee11311f65438b778adf222c98009b051853f`. Host: AMD Ryzen 7 PRO
8840U. Compiler: GCC 16.1.1 20260430, C23.

The registered source-swarm fixture downloads a content.v2 package manifest
and one chunk, closes the engine and store, then reopens from the same CAS
directory and finishes the download. Its existing assertions require manifest
first, one present chunk after restart, exact completion, and cumulative
verified payload bytes equal to the manifest plus every chunk. A reversible
patch prints the service ledger's verified payload total before and after
resume, without changing any acceptance assertion.

```bash
git apply --check docs/experiments/2026-09-25-chunk-resume-measure.patch
git apply docs/experiments/2026-09-25-chunk-resume-measure.patch
make CC=gcc -j4 t-fast ONLY=zcode_swarm \
  > test-tmp/chunk-resume-measure.log 2>&1
git apply -R docs/experiments/2026-09-25-chunk-resume-measure.patch
git status --short
```

The run printed:

```text
CHUNK_RESUME_PROBE fresh_payload=1882 preverified=1333 resume_payload=549 avoided_on_resume=1333
```

The resumed phase fetched 549 verified payload bytes, rather than 1,882
payload bytes for a fresh download: 1,333 bytes, or 70.8%, were already
verified in CAS and avoided on resume. The 1,333 bytes had been transferred
before restart, so this is a **resumed-phase saving**, not a claim that the
two sessions together used 1,333 fewer bytes than one uninterrupted fresh
download. The counter excludes request/response framing, retransmissions,
transport headers, and verification CPU time. The fixture uses an honest
loopback peer; it does not measure a three-host fleet transfer.

All four matching registered groups passed with zero skips. The captured
log SHA-256 is
`256197ca3b91719f65ef3dd12a06e585aa84555b055714733e4aff6d64661a5c`;
the patch SHA-256 is
`b3bf8f80e2cda371a4a4ee277eb69e63aec43dad3f4b5e727f2d7eecca538bb4`.
The tracked test source was restored to SHA-256
`1cfba1322d0734ba4ffd5d036f116ef04e43e46766329ae0982db4db8402c9b3`.
The run's reported 51.0 s test wall time occurred under concurrent landing
proof load and is not a standalone throughput benchmark.
