<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Retained gateway reproduction and tunnel fixture acceptance

Observed 2026-10-15 on Linux x86_64, AMD Ryzen 9 7950X3D.
Source: `74bdde92b7926fab5cee262212c23464750396db`.
Parent: `890771c49a40a51ebe3ebd116d1176db91130b44`.
No production deployment or new live two-host trial was performed.

## Two fresh retained builds

Both runs used the canonical qualification script under `devbuild --wait`,
with `VENDOR_CC=gcc`, `DEVBUILD_KEEP_SCRATCH=1`, explicit source SHA and
`--keep-worktree`. Train names:

- `gw-mailbox-74bdde92b-repro-a-20261015`
- `gw-mailbox-74bdde92b-repro-b-20261015`

Both exited zero with this identical verdict:

```text
verdict: PASS sha=74bdde92b7926fab5cee262212c23464750396db gw=50a4ca0d07b5eec8db5f57afced08685a1c1ae7d52a6b8b00c959843294e8948 front=712a73603b6786faa3c9719c3f309df035f27dca1168ebe8040f7591767ff5f1 node=2356e6b8833dbb3d5f54e975426d4c16b1b9961ffec8e282f7fed10d21df2457 (pass=46 fail=0 skip=0)
```

Direct `cmp` also found all bytes identical in the gateway, front, node
and `z23.debug`. This includes every node ELF section, embedded path,
build ID, comment and debuglink. Build ID:
`db5255c290e0f5e29d0519dfe34dd04b286bdee7`.
Debug SHA256:
`814b5aad6c6e7cac064bf270ce7db1d625d5c4f5dee3bbb2dc9a3c6964349141`.
Node size is 36,138,992 bytes. File mtimes differ, as expected for separate
builds; they do not alter these bytes.

Tor pin is `f4e28103c0eb9016e0b500d02486b7a59d20ee5d`.
Both retained `libtor.a` files compare equal, SHA256
`bcb14ead084d3f38b74c69cae9a19413ea1d19463f271545cc8a179a7996dbf3`.
The host reports GCC 14.2.0 and Clang 20.1.8. Both node comment sections
contain GCC 14.2.0 and GCC 15.2.1 identifiers. The canonical prime can reuse
pinned vendor archives; these are fresh project builds, not independent
from-source vendor rebuilds. No earlier missing binary is reconstructed
or diagnosed by this comparison.

Raw retained evidence is in the qualification lane under
`build/scratch/gateway-mailbox/retained-qualification/`:

| File | SHA256 |
| --- | --- |
| train-a.log | 7b38b5431de5f12becb7ebffabadd9ce5efee4b1981bf3d840853ce0ffdb38c5 |
| train-b.log | 2374fc0ed5164d5fa2edea0ba11b7e4761ece5853ddb47c34d6b8db3fdd71b3a |
| reproduction.txt | 8b4aafafe1fa5435fc0c3b8328c195734cd3c2261d3171f79630396d960e62b1 |

Images, debug sidecars and isolated runtime scratch remain retained.
The gateway harness establishes its stated HTTP, OAuth, credential-refusal
and cleanup checks. It does not establish tunnel rollout acceptance.

## Focused tunnel fixtures

Executed through admission:

```sh
env VENDOR_CC=gcc devbuild --wait make t-fast-exact \
  ONLY=device_host_runtime,device_host_psk,device_host_bridge,device_command,native_tunnel_export
```

Verbatim final result:

```text
SUITE VERDICT mode=cold groups_total=1329 groups_ran=5 groups_cached=0 groups_gated=1324 groups_failed=0 self_skips=0 env_unobserved=0 load_flaky=0 toolkey=83d57dfdeb13
ALL TESTS PASSED — 0/5 groups failed, 0 skipped (40.3s wall, 28 workers) [--exact filtered]
```

These registered fixtures include actual local receiver/client processes,
wrong-secret refusal before target connection, revoked plaintext exclusion,
raw-EOF truncation, cancellation, pre-authentication slot limits and exact
export checks. They do not substitute for two-host OpenSSH acceptance.

An initial run exited 2 before tests because the source-identity guard
reported a superseded build while the rollout draft was being edited.
After freezing source, the complete focused command above exited zero.
No guard or assertion was weakened.

| Retained log | SHA256 |
| --- | --- |
| tunnel-focused.log | 53e7e438475e630467620e8aff04759d06fe39bbb9f6222598f6605f66813a88 |
| tunnel-focused-stable.log | 7617df2c2bb2d2df3e94b724b1d6fe6d8e18955a974ba8fae2dfebf02c986e1a |

## Previous live-pair boundary

The separate retained R1-to-R2 trial at
`build/handoff/twohost-trial-20261015` in the primary checkout was read
and its complete `SHA256SUMS` checked successfully. Its `RESULTS.txt`
hash is `595c3fc6dc0b4a0e8322cd44bb4242e7adf7df33dcc2b6b15738a72de9afd5c3`.

It records ten alternating tunnel/direct measurements, authenticated
receiver EOF, post-revoke refusals and cleanup. It also records package
client `signal_queue_failed` in seven of twelve sessions, despite engine
EOF and complete custody cleanup. Killed-proxy and traffic-revoke
negatives were not run. Both pairings were revoked. These facts establish
a measured earlier pair, not acceptance of the candidate above or a
persistent usable fleet route.

The [tunnel section of the fleet guide](../FLEET.md#tunnel) requires fresh per-host
approval and acceptance before publication as a working fleet procedure.

## Integration and publication continuation

After reviewing published main
`16f864d87ec5701a28a296407649ac24c638ecb8`, merge candidate
`c27c4746c` regenerated the conflicting capability inventory through the
canonical target. The first generation attempt refused the unresolved index;
after staging the upstream generated artifact, regeneration succeeded.
No hand-edited inventory counts were retained.

The gateway, both gateway shards, fleet board, mesh-status wire, mesh-terminal
attach and syncdiag RPC groups passed:

```text
SUITE VERDICT mode=cold groups_total=1329 groups_ran=7 groups_cached=0 groups_gated=1322 groups_failed=0 self_skips=0 env_unobserved=0 load_flaky=0 toolkey=83d57dfdeb13
ALL TESTS PASSED — 0/7 groups failed, 0 skipped (45.3s wall, 28 workers) [--exact filtered]
```

The earlier two identical retained gateway builds remain bound to their
original candidate SHA; this integration test does not extend their image
identity claim to a different source tree.

The public `agent-host-tunnel-howto` wiki revision
`f3de07fa5716d7ecfc35675f654b8ce179af6347d21bf5c75e9979604e8495d5`
was published with explicit historical-pair and deployment limits.
Discovery returned that exact revision; thirteen exact reads reconstructed
6,996 bytes with SHA3-256
`c64cee59697fd351777bbbcd9828405d5703f838a569d00acf778a3b626fdb6b`,
matching the receiver's write receipt. This is readback/hash evidence, not
an independent signature-verification claim.
