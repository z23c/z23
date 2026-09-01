# OS-A1 — the privileged-transition authority-receipt idiom

**Law 7:** a self-asserted artifact never authorizes a privileged state
change. Authority requires a receipt that a prior pass derived
INDEPENDENTLY and bound to `{artifact digest, context anchor, the EXACT
running-binary image}`, re-checked fail-closed at use time through a
datadir capability fd (pathnames are locators, never authority).

## The reusable idiom — `platform/modules/util/authority_receipt.{c,h}`

- `authority_receipt_running_binary_digest()` — SHA3-256 of the running
  executable image (`/proc/self/exe`), race-free direct `open` (a path
  `readlink` reintroduces TOCTOU).
- `authority_receipt_write_atomic()` — atomic keyed write under a datadir:
  tmp → `fsync(file)` → `rename` → `fsync(dir)`.
- `authority_receipt_read_fixed()` — reads EXACTLY N bytes of
  `<datadir_fd>/<name>` through the capability fd (`openat`
  `O_NOFOLLOW`); a longer or shorter file is rejected.
- `struct authority_receipt_header` (208 bytes: `schema[48] + artifact[32]
  + anchor[32] + detail[32] + verifier[32] + digest[32]`) is the canonical
  header for new consumers. `authority_receipt_header_seal_and_write()`
  fills `verifier_binary_digest` + `receipt_digest` and writes it
  atomically; `authority_receipt_header_authority_available()` re-verifies
  the self-binding digest, requires the running binary to equal
  `verifier_binary_digest`, then requires schema/artifact/anchor/detail to
  equal the caller's expected values — any missing, tampered, foreign, or
  different-binary receipt fails closed.

`engine/composition/src/consensus_state_replay_receipt.c` and
`engine/composition/src/consensus_state_producer_receipt.c` consume the three idiom
primitives (their own typed 344-byte payload, digest, and SQL derivations
stay in the replay module — the generic contract binds the digest, not the
field layout).

## The lint gate — `check-privileged-transition-receipt`

**Contract:** every native command leaf whose spec is
`ZCL_COMMAND_AUTH_OWNER` **and** effect `ZCL_COMMAND_EFFECT_MUTATE` or
`ZCL_COMMAND_EFFECT_DESTRUCTIVE` is a candidate privileged transition. Each
such leaf must have a disposition in
`tools/lint/privileged_transition_receipt_baseline.txt`:

```
<leaf.path>  receipt:<relative_file>   # transition; <file> MUST call authority_receipt_*_available(
<leaf.path>  exempt:<one-line reason>  # not an artifact-install transition
```

A new owner-mutating leaf with no disposition fails the gate. For a
`receipt:<file>` line the gate additionally asserts `<file>` contains a
call matching `authority_receipt_.*_available(` or the
pre-generalized `consensus_state_replay_receipt_authority_available(`.
Enumeration parses `engine/composition/commands/*.def` (build-free): a spec qualifies
when its text contains `ZCL_COMMAND_AUTH_OWNER` and
(`ZCL_COMMAND_EFFECT_MUTATE` | `ZCL_COMMAND_EFFECT_DESTRUCTIVE`); READ-form
macros hard-code `EFFECT_READ` and are excluded by construction.

**Consumers that must bind `receipt:` as they land:** bundle ACTIVATE
(already calls the contract, `engine/composition/src/consensus_state_snapshot_install_activate.c`),
hot-swap Phase-3 reopen, `make deploy` generation publish, and the ADR-0004
App-cartridge activation.

Tests: group `authority_receipt`
(`tests/harness/src/test_authority_receipt.c`) covers write/read round-trip, the
exact-length rejection rule, header seal/verify (including a flipped
expected input and a flipped on-disk byte both failing), binary-mismatch
rejection, and running-binary-digest determinism.
