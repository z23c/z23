# Zcash proving parameters — what your node needs and what it does not

This page explains a change to how the node handles the Zcash zero-knowledge
parameter files: what needs them now, what does not, and how to get them if
you want the part that still does. If you only came here because a mainnet
node parked at boot, read the next two sections and stop.

## What changed and what it means for you

Previously, a mainnet node with no parameter files at `$HOME/.zcash-params`
parked at boot: no P2P listener, no RPC, no peers, held at a named gate
(`crypto_params_missing` in `config/src/boot.c`). Getting the files was a
precondition for running the software at all.

That gate is gone. A mainnet node with an empty `$HOME` now boots, opens its
listener, syncs headers and blocks, validates every transaction — including
shielded ones — and serves peers normally. The only capability it lacks is
**creating** a new shielded transaction of your own.

## The short version

If you only ever send and receive transparent ZClassic, or you only receive
shielded funds without spending them, you need nothing. Run the node the
normal way; nothing in this page is required reading for that case.

If you want to send a shielded transaction — `z_sendmany` with a shielded
input, or shielding funds into a new shielded output — see
["Installing the proving parameters"](#installing-the-proving-parameters-if-you-want-to-send-shielded)
below.

## Why a validating node needs no parameters

A Zcash parameter file is two things concatenated: a verifying key, followed
by a much larger proving key. Consensus validation — checking a shielded
proof someone else already made — reads only the verifying key. Creating a
new shielded proof needs the proving key as well, and that is the only thing
the proving key is for.

The verifying-key prefix has an exact, fixed size:
`groth16_vk_read_raw()` in `lib/sapling/src/bls12_381.c` reads precisely
`868 + ic_len * 96` bytes and stops. Measured against the real files:

| file | verifying-key prefix | ic_len | full file size |
| --- | --- | --- | --- |
| `sapling-spend.params` | 1636 bytes | 8 | 47958396 bytes |
| `sapling-output.params` | 1444 bytes | 6 | 3592860 bytes |
| `sprout-groth16.params` | 1828 bytes | 10 | 725523612 bytes |
| `sprout-verifying.key` | 1449 bytes | (whole file — PHGR13, not Groth16) | 1449 bytes |

Total verifying-key material: 6357 bytes, against roughly 777 MB of
parameter files. Everything past that prefix is proving-key material, reached
only through `sapling_get_spend_pk()` / `sapling_get_output_pk()` — and the
only callers of those two functions are on the path that builds a shielded
output you are sending. Nothing in block validation, header sync, or peer
serving touches them.

Those 6357 bytes are now compiled directly into the node binary, generated
into `lib/sapling/src/params_vk_embedded.c`. Each blob carries its own
pinned SHA-256, checked by `sapling_install_embedded_vks()` before the bytes
are parsed, so a build that patched one of these arrays would fail closed
rather than validate proofs against the wrong key.

The reasoning for compiling them in rather than reading them from a file: a
verifying key that every node must use identically is a consensus constant,
in the same sense the checkpoint table already baked into this repository
is one. Two nodes with different verifying keys are, by definition,
validating different networks. A constant every node must agree on belongs
in the source tree — not in a large file fetched from a host nobody in this
project controls.

## What you lose without the proving parameters

With no proving keys loaded, the native prover reports itself
`NATIVE_PROVER_UNINITIALIZED` and `zclassic_sapling_prover_is_ready()`
returns false. `app/controllers/src/wallet_shielded_send.c` checks that
before doing any coin selection or touching spend state, and if it is false
it refuses the send with a named error —
`Shielded proving unavailable (backend=..., status=...)` — instead of ever
attempting to emit an unproven shielded output. There is no path that
produces a broken or unverified shielded transaction; the send simply does
not happen.

The node also names this a standing blocker at boot,
`shielded_spend_unavailable`, under `crypto.params`. That means the
condition is visible in the node's own status reporting from the moment it
starts, not something you only discover the first time you try to send
shielded funds.

Regtest and testnet never enforced the old params gate and still do not;
none of the above is new for those networks.

## If the parameter files are present but corrupt

A file that is there but wrong is a different situation from a file that is
absent, and the node reports it as one.

Each of the four files has a pinned SHA-512 checked before any of its bytes
are parsed. If a file fails that check — a truncated or interrupted download,
disk damage, tampering — the node **refuses the whole directory**. No byte of
a file that failed its pin is ever parsed or installed, on any network,
including the one file that had no pin until recently.

Refusing the directory does not stop the node. Verifying keys are compiled
in, so validation runs from those instead and the node syncs, validates and
serves exactly as before. What the corrupt file was carrying that the binary
does not is the proving key, so the node reports the same single capability
blocker a node with no parameter directory reports,
`shielded_spend_unavailable` under `crypto.params` — with a reason that says
the parameters were REFUSED rather than missing, so you know to re-fetch
rather than to install for the first time. Re-run
`tools/scripts/zcash_params.sh verify` to see which file failed.

A corrupt parameter file therefore costs you the ability to *send* shielded
funds until you re-fetch it, and nothing else. It is not a reason for a node
to stop validating the chain.

The one condition that does stop the node is the compiled-in verifying keys
failing *their* SHA-256 check. That means the binary itself cannot verify
shielded proofs, and a node that cannot do that must not pretend to validate;
it names `params_missing` and parks alive-degraded.

## Installing the proving parameters (if you want to send shielded)

Use `tools/scripts/zcash_params.sh`. It has two subcommands you need:

```bash
tools/scripts/zcash_params.sh verify [dir]
tools/scripts/zcash_params.sh install <src-dir> [dest-dir]
```

`verify` checks the four required files in `dir` (default
`$HOME/.zcash-params`; the node's own `-paramsdir=<dir>` flag points it
elsewhere too) against the pinned sizes and SHA-256 digests below. `install`
copies the same four files from a directory you already have them in,
verifying every file both before and after the copy.

Exactly four files are required. A fifth file some distributions ship,
`sprout-proving.key`, is **not** one of them and is not checked.

| file | bytes | sha256 |
| --- | --- | --- |
| `sapling-spend.params` | 47958396 | `8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13` |
| `sapling-output.params` | 3592860 | `2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4` |
| `sprout-groth16.params` | 725523612 | `b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50` |
| `sprout-verifying.key` | 1449 | `4bd498dae0aacfd8e98dc306338d017d9c08dd0918ead18172bd0aec2fc5df82` |

They total roughly 777 MB. They are the public outputs of the Zcash
multi-party parameter ceremonies — the same files any Zcash-family node
uses, not something specific to this project. If this machine already runs
`zcashd` or `zclassicd`, they are likely already at `~/.zcash-params`; check
before fetching anything.

Otherwise, get the four files from wherever you already trust — a copy from
another machine you control, your distribution's package, or any other
source — and run `verify` (or `install`, which verifies for you) before
starting the node with shielded sending in mind. There is deliberately no
flag to override a hash mismatch: these are cryptographic keys, and wrong
bytes are a security failure, not an inconvenience.

Be clear about what this script does and does not do: it moves and checks
bytes you already obtained. It pins no download host, no DNS name, and no
certificate authority, and it does not fetch anything for you. The project
can tell you whether the bytes you found are the right bytes; it does not
hand you a place to find them. That half of the job is still yours.

## Why not fetch these over our own network

This project has its own P2P file delivery for bootstrap artifacts (see
[`docs/ROM_DELIVERY.md`](ROM_DELIVERY.md)), and it can move bytes at the
right scale in principle — 8 MiB chunks, up to 32 GiB per artifact, far more
than the ~777 MB parameter set needs. It does not carry the parameter files
today, for three separate reasons:

- The artifact registry classifies a served file into exactly two kinds by
  its exact filename — a consensus-state bundle or a header-chain seed
  (`rom_seed_classify()` in `lib/net/src/rom_seed.c`). There is no artifact
  kind for a parameter file, so nothing would admit or serve one yet.
- The ZCODE package store is a separate, local-only content store today,
  capped at 64 MiB per package — well under the ~777 MB parameter set, and
  not reachable from another node regardless of size.
- The default file-service seed list is empty. A fresh node with no
  `-fileservice` or `-addnode` pointed at a peer has nobody to ask, for this
  or any other artifact.

Fetching the proving parameters over this project's own network remains the
right long-term home for them, and this change makes that a plain
optimisation rather than a prerequisite: a node now reaches the network,
syncs, and validates on its own, with or without that fetch ever landing.

## Maintainer regeneration

`lib/sapling/src/params_vk_embedded.c` is generated, not hand-written. To
regenerate it from a verified parameter set:

```bash
tools/scripts/zcash_params.sh vk-extract <params-dir> lib/sapling/src/params_vk_embedded.c
```

This is a maintainer-only path: it reads a proving-parameter directory
already on the machine and re-derives the verifying-key prefixes committed
to the repository. It does not download anything and is not part of a
normal node's boot or an operator's day-to-day use. Regenerated output is
expected to be byte-identical for the same input parameter set — a diff in
the committed file should mean the upstream parameters changed, not that the
extraction is nondeterministic.
