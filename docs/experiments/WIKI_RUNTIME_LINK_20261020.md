<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Wiki runtime link experiment — 2026-10-20

A fixed-object Linux/GCC pilot reduced the finite wiki coordinator's link work
by replacing direct inclusion of all node objects with selective extraction
from a regular indexed archive. The wiki main and trace constructor object
remained explicit link inputs. This experiment did not modify the product
Makefile or publish a canonical executable.

## Environment and identities

- CPU: AMD Ryzen 9 7950X3D 16-Core Processor.
- Compiler: `cc (Ubuntu 14.2.0-4ubuntu2~24.04.1) 14.2.0`.
- Archive tool: compiler-selected `gcc-ar`, GNU Binutils 2.42.
- Date: 2026-10-20; A began 09:03:13Z (05:03:13-04:00).
  Regular-archive qualification ran 09:36:27Z–09:36:40Z
  (05:36:27-04:00–05:36:40-04:00).
- Separate `devbuild --wait --project z23 --class normal --cpu-limit 4`
  admissions reserved 8 GiB. A observed `cpu.max=400000 100000`, `nproc=28`,
  affinity `2-15,18-31`. Only A recorded those cgroup/affinity observations.
  Final B used the same explicit `--cpu-limit 4` invocation, but its actual
  cgroup CPU limit and affinity were not separately recorded. Both admission
  logs report CPU tokens 8 and RAM 8G; tokens do not establish actual CPU quota.
- Frozen checkout during A capture: `e2dd4dbb74a612cb4d07c54612567c7f1ef4e87b`.
- Object session: `source_id=772ea458adee043007d79bc38148c6a0ecbb705b50c4711d79a3e23024eef1cb`,
  `complete=1`, `profile=node-c23-v1`.
- Session mutation: `e0d4c17cf4036174e674ea75c58cf0a0788a19635a1b0fe305298a5dd0d9a5a0`.
- Compiler identity: `f55a6eb065a4bb514feacd3c0b2a0bf149150f51757dc325fcc520525f228571`.
- Compile epoch: `ee77b4f2b42135e57b8633c974f99e8a049b1289f5600405361e4d8b04788b49`.
- Session flags digest: `e3c57fcebaffd9bb6576ceab35da012f58f35b80f3e1b0eaf99a92516b905ca3`.

The 2642 existing objects totaled 191170952 bytes. Their pre/post SHA256
manifests matched. A private snapshot retained those bytes and vendor archives;
its size was 235947674 bytes. The compiler wrapper was copied and its version
matched A. B no longer depended on a frozen source checkout.

Captured current-Make source identity was
`9bebf015958e9cded7d37266a1f241f5a457497a37477966d53e8fa243e4150f`.
It differs from the complete object session above. These measurements establish
fixed-object behavior, not a clean build from that current source identity.

## Method and results

A passed all objects directly to the captured compiler command. B created a
regular archive with `gcc-ar qcsD`, then linked the wiki main and
`platform/modules/util/src/trace.o` explicitly before that archive. Both retained
the captured libraries, `-O3`, `-march=x86-64-v3`, `-flto=auto`, PIE and link flags.
No stubs, weak replacements, LTO removal or coverage exemptions were used.

| Operation | Wall seconds | Peak RSS, KiB | Executable bytes |
|---|---:|---:|---:|
| A: direct whole-node object link | 123.84 | 812940 | 139507704 |
| B: regular archive construction | 5.81 | 37260 | — |
| B: selective link, explicit trace root | 1.71 | 92060 | 2416616 |

The regular archive contained all 2641 common members. A sorted basename
multiset comparison preserved all members, including 22 repeated-basename
groups. Archive magic was `!<arch>`, not the thin-archive format.

A regular archive plus explicit trace root is the final measured candidate.
A preceding thin-archive experiment is retained as intermediate evidence only.

## Executed behavior checks

The real A and selective CLIs ran against a deterministic C23 peer executable,
private owner-marked `/tmp/zcl23-*` participant directories and a private signed
post store. No node, network service, operator signing key or canonical store
was used. The fixture exercised both writers, two superseding revisions and
cross-reader verification of production Ed25519 signatures.

- A, thin B and final regular-plus-trace B returned propagation success.
  Every successful receipt retained `full_qualification=false`.
- Each rejected a tampered signature with exit 1 and `post-crypto-refused`.
- Usage and malformed-plan observations matched between A and thin B.
- Final B retained `trace_otlp_logs_ctor` and `trace_install_log_mirror`;
  disassembly and initialization-section evidence are retained.
- A small observer linked with the same trace root reported
  `mirror_installed=0` with `ZCL_OTLP_LOGS` unset and `mirror_installed=1` with
  `ZCL_OTLP_LOGS=1`. This tests hook installation, not general telemetry parity.

The first positive fixture failed because `json_get_str(NULL)` returns an empty
string: absent first-revision `supersedes` was mistakenly decoded. Retained
repair checks member presence/type and requires a valid parent for revision 2.
Invalid expected-state arguments are rejected rather than interpreted as fail.

## Retained reproduction and evidence

Private evidence packet label: wiki-link-ab-20261020.ka3i4w.
Use its captured response files and private snapshot; do not substitute objects
from another epoch. attempt2/run.sh, attempt4/run.sh,
attempt4/positive-fixed/run.sh and attempt5/run.sh retain exact commands.
attempt2/run.sh successfully produced A, then stopped at thin-archive member
inspection; it is retained evidence, not a complete successful replay script.
Any rerun requires the host's current admission and storage contract, valid
input paths and the recorded distinction between source and object identities.
The scripts document executed commands; reproduce into new empty output paths
and preserve the original packet. `qcsD` appends to an existing archive, so
rerunning these hard-coded scripts in place is not a clean reproduction.

| Evidence | SHA256 |
|---|---|
| Final regular/trace `attempt5/evidence.sha256` | `a923c340d81555e177f30b9308f039b34291596efb7a6329ac8c28f1140dc3e6` |
| A/thin positive/tamper `attempt4/positive-fixed/evidence.sha256` | `b569b08f73e75cfb1689ee02b13b247f4d09b15eae151b17599033502ee0ffce` |
| Private object manifest `attempt4/objects.snapshot.sha256` | `2621767227ed8a5daf14cf09a93112828bdf2bbdb90fcd714d63bd267a65b59b` |
| Private vendor manifest `attempt4/libraries.snapshot.sha256` | `125d1623e5c83891e1d26b7db7c198100b3a4605e46dee7d9ffb034e18aae07d` |
| Direct A executable | `3e94664cb4d8bd93bc4b10b1a190e67ac95d6dd97a1bc310bfbd8f1a19921651` |
| Final regular/trace B executable | `24a8e3ff5056651fa3b43026e05d3064518260b098da69ef66b79f3150dee820` |
| Repaired peer fixture source | `602cfb52249cf087690170c064928cf5bfe36a7d26d92936620db2b9e5cc4f80` |

## Limits and next qualification

A and B ran sequentially in separate admissions, with differing cache warmth
and uncontrolled concurrent host load. Queue waits are excluded from link
measurements. The initial thin B waited 715.412 seconds; final regular-plus-trace
B waited 199.526 seconds under normal 8 GiB admission. These are distinct jobs.
This is a single pilot, not an alternating statistical comparison.
Thin-archive path repair and a cancelled queued request remain recorded; no
running unrelated job was cancelled.

Removed node composition/crypto registration constructors were absent from B;
the exercised coordinator uses direct crypto and subprocess calls. The explicit
trace root preserves its observed opt-in hook. These checks do not establish
all telemetry behavior, full lifecycle acceptance, fleet propagation or a
production/current-source build. A production recipe must retain source/epoch
publication checks, portable direct-link fallback, and independently exercise
the actual published wiki CLI with these isolated positive/tamper controls.
