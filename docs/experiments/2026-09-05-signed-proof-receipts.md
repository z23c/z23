<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Signed push-proof receipts

## Question

Push admission read a receipt whose seal was a keyless SHA3-256 digest over
the receipt's own bytes. Two things follow from that, and both were true:

1. Anything that can write `.cache/zcl-dev-proof/receipts/` can write a
   receipt the hook admits. Every coding-agent lane on this box runs as the
   operator uid, so "anything" is every lane, every editor plug-in, and every
   script that ever ran here.
2. No other host can hand this host evidence it can attribute. A receipt from
   another box is byte-shaped like a local one and says nothing about who ran
   the proof.

Can the receipt carry an identity — one key per box, one operator-local trust
list — without adding a dependency, a chain fee, a network call, or any work
to the hook's no-shell/no-build/no-wait contract? And what does that cost?

## Environment

- UTC: `2026-09-05T06:07:26+00:00`
- Host: Linux 6.8.0-138-generic x86_64
- CPU: AMD Ryzen 9 7950X3D 16-Core Processor
- Compiler: gcc (Ubuntu 14.2.0-4ubuntu2~24.04.1) 14.2.0, `-std=c23`
- Baseline commit: `6c5fd07b2`

## What was built

`tools/dev/dev_proof_signer.c` holds one Ed25519 keypair per box under
`platform_state_root()/proof-signer/signer.ed25519` (mode 0600, created with
`platform_private_file_create`, outside every worktree), and one trust list
beside it, `signers.allow`. The record grew a fixed 96-byte trailer —
`signer_pubkey[32] || signature[64]` — appended to the unchanged 664-byte v1
body, whose format version stamp moved from 1 to 2. The signature covers the
domain string `zcl.dev_proof_receipt.v2` followed by that whole sealed body,
so a single flipped byte anywhere in the record — including in the stored
digest — is refused as `signature_invalid` rather than surfacing later as
whichever structural check the edit happened to trip.

`zcl_dev_proof_receipt_seal()` and `zcl_dev_proof_receipt_validate()` kept
their names and signatures, so `tools/dev/dev_proof.c` needed no edit: it
sizes its buffers with `ZCL_DEV_PROOF_WIRE_BYTES`, and only the number behind
that name moved.

The primitives are the tree's own: `ed25519_keypair` / `ed25519_sign` /
`ed25519_verify` from `core/modules/crypto`, `rng_fill` from
`platform/modules/platform`, `platform_state_root` for custody. Nothing was
vendored.

## Cost

Measured with a 200-iteration loop over the real seal and validate entry
points, and with the pre-change code compiled from `6c5fd07b2` and measured
the same way. Six runs of each, in two sessions an hour apart, on a box that
was also compiling other lanes — the ranges below are what that spread looks
like, not a quiet-machine best case.

| | before (v1) | after (v2) |
|---|---|---|
| Receipt on disk | 664 bytes | 760 bytes |
| `..._seal()` | 2.0–3.1 µs | 1,962–2,146 µs |
| `..._parse()` + `..._validate()` | 2.0–2.3 µs | 1,850–1,988 µs |
| `z23-git-hook --selftest` p95 (open, read, parse, validate) | 8 µs | 1,961–2,821 µs |

Roughly 2 ms per admission and 2 ms per seal. Two Ed25519 group
operations dominate: the verify itself, and re-deriving this box's own public
key from its seed on every call so that the own-key-is-always-trusted rule can
be evaluated. `docs/CRYPTO_PERF.md`'s standing measurement for this tree's
`ed25519_verify` is ~710 µs, which accounts for both halves; the remaining
tens of microseconds are the key-file and allowlist reads. Admission runs once
per push and sealing once per proof (a full proof is minutes), so this is not
on any loop worth optimizing yet. If it ever is, memoizing the derived public
key per process halves it.

## Cross-host truth, as it actually is today

This lane changed no root. What follows is what the producer computes now, read
out of `tools/dev/dev_proof.c`, because the answer decides whether a signed
receipt from another box could ever be reused as evidence here.

`compiler_root`, `flags_root` and `build_graph_root` are three
domain-separated SHA3-256 hashes — `zcl.dev_proof_compiler.v1`,
`zcl.dev_proof_flags.v1`, `zcl.dev_proof_build_graph.v1` — of the **content of
one and the same file**, `<root>/build/dev-loop/restart.env`
(`dev_proof.c:2388-2397`, via `hash_file` at `dev_proof.c:820`). They are not
three independent measurements; they are one measurement under three names.
That file is written by the `$(DEV_RESTART_PLAN)` recipe in the Makefile and
carries `CC`, `COMPILER_ID`, `BASE_GENERATION`, the dev and test
`CFLAGS`/`LDFLAGS`/`LIBS`, and the epoch-keyed object, link-response and
base-relocation paths.

Its `COMPILER_ID` comes from `tools/dev/build-epoch-key.sh compiler-id`, whose
preimage binds, for every resolved compiler tool, both the tool's content
digest **and its absolute resolved path** (`fingerprint_tool`,
`build-epoch-key.sh:154-172`), plus the verbatim output of
`-print-search-dirs` and `-E -x c -v -`, which are lists of absolute system
paths. So an absolute path enters `compiler_root`, alongside a real content
digest of the toolchain.

`environment_root` (`dev_proof.c:1880`) hashes the name and value of nine
environment variables: `CC`, `CFLAGS`, `CPPFLAGS`, `LDFLAGS`, `LANG`,
`LC_ALL`, **`PATH`**, `ZCL_FAST_CC`, `ZCL_FAST_JOBS`.

Therefore: two hosts with different compilers can never produce equal roots,
and two hosts with byte-identical compilers still cannot unless those
compilers resolve to the same absolute path — and their `PATH` matches
exactly, which for two boxes with different usernames it does not. Signing
makes a receipt **attributable**; it does not make it **portable**. Making a
proof from box A usable on box B needs the key to stop binding host-specific
strings, and that is the commuting-ticket lane's work, not this one's.

That gap is closed. `compiler_root` is now the toolchain capsule root, the
flag and build-graph roots come from the build plan with the checkout's
location written out of it, and `environment_root` no longer binds `PATH`.
Two boxes with the same capsule over the same tree produce the same four
roots. See the receipt paragraph in [`../DEVELOPING.md`](../DEVELOPING.md);
receipts written under the meaning described above are refused by name as
`receipt_schema_old`.

## Two allowlists, on purpose, for now

The fleet already has a signed, allowlisted worker path:
`metaverse.build.worker.approve` writes a `signer_pubkey` hex allowlist that
`engine/services/src/build_fabric_worker.c` checks before admitting a build
receipt. This lane deliberately did not wire the push-proof signer into it.

They answer different questions. The build-fabric allowlist says which workers
this operator will *dispatch build actions to* — it is fleet state, it lives in
the node's database, and it is administered through a command that mutates
that database. `signers.allow` says whose push-proof receipt this **checkout**
will admit, and it must be readable by a Git hook that opens no database, runs
no node, and must answer in milliseconds with the node stopped. Collapsing
them today would either give the hook a database dependency it must not have,
or give fleet worker admission a plain-text file outside the node's state.

They should converge once the canonical lifecycle owns a signed fleet identity
that both surfaces can read cheaply — one key per box, published once, trusted
in both places. Until then, adding a box to one list does not add it to the
other, and that is a fact to state rather than a bug to hide.

## What the Windows gate does not see

`make check-windows-cross-syntax` passed, and it did not compile any of this
work's hook-side files. Its scan roots are `core engine contexts cognition
platform tools/command`
(`tools/lint/check_windows_cross_syntax.sh:79`), so `tools/dev/` — which holds
`z23_git_hook.c`, `dev_proof_receipt.c` and the new `dev_proof_signer.c` — is
outside them, even though the hook is the one binary the repository installs on
Windows. The gate was not widened here; that is a decision for whoever owns
that gate's scope.

Running `x86_64-w64-mingw32-gcc -std=c2x -fsyntax-only` over those three files
by hand, with the gate's own flag set: `dev_proof_signer.c` and
`dev_proof_receipt.c` are clean, and `z23_git_hook.c` reports two errors, both
`TIME_UTC undeclared` in `running_eta` and `sample_clock_ns`. The identical two
errors reproduce on the `6c5fd07b2` version of that file, so they are
pre-existing and untouched by this lane — but they are also exactly the class
the gate exists to catch, invisible only because of where the file lives.

## Migration

Every receipt already cached is a v1 record. It parses, and it is refused by
name as `receipt_unsigned` — from the hook on one line, and from
`dev proof status`. Re-proving that commit/base pair writes a signed one.
Child receipts are untouched: same magic, same version, same bytes, so a
re-seal does not orphan the child evidence already on disk.

## Evidence

- `make -j8 t-fast ONLY=dev_proof_signer` — the new registered group: sign and
  validate round trip; a flipped byte in a root, a dimension count, the
  timestamp, the completeness flag, the stored digest, or the signature is
  `signature_invalid`; a v1 record is `receipt_unsigned`; a foreign key is
  `signer_unknown` until its line is in `signers.allow`; a key file that is not
  a private 32-byte seed is `signer_key_unreadable`; and the installed
  `build/bin/z23-git-hook` binary, driven as a real pre-push hook over a real
  two-commit repository, refuses the forged and the unsigned record and admits
  only the one this box signed.
- `make -j8 t-fast ONLY=impact_composition` — the existing receipt admission
  proof, now running against an isolated state root.
- `build/bin/z23-git-hook --selftest`.
