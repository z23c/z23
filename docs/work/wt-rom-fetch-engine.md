# ROM fetch engine — the client side of ROM delivery

Client half of [`docs/ROM_DELIVERY.md`](../ROM_DELIVERY.md): pulls the
two-builder-verified consensus-state bundle from a seeding peer instead of
paying the from-genesis fold. The serving side (`core/modules/net/src/rom_seed.c`,
`fs_serve_rom_chunk`) and the fetch side (`core/modules/net/src/rom_fetch.c`,
`engine/controllers/src/rom_fetch_controller.c`) are both implemented; do not
build another transport.

## Trust model (inviolable — do not create a third activation door)

The fetch engine is an **untrusted-transport downloader**:

1. It commits to digests before fetching — `(chunk_root, whole_sha3, size)`
   come from operator input or a discovered manifest and are the only values
   carried into verification.
2. It downloads chunks (transport-MAC-verified per chunk, fail-closed).
3. After the whole file lands it re-hashes it: per-chunk SHA3 fold ==
   `chunk_root` AND whole-file SHA3 == `whole_sha3` AND size == manifest —
   any mismatch unlinks the file, no partial trust
   (`docs/ROM_DELIVERY.md`).
4. It hands the verified path to the existing installer
   (`-install-consensus-bundle=PATH` → `boot_install_consensus_bundle`),
   whose receipt / `CHECKPOINT_CONTENT` authority is the only activation
   door. This engine never calls the activate path itself, never touches
   consensus validation, and never installs bytes the operator did not
   commit to.

Per-chunk content digests are not on the wire: the serve side binds the true
per-chunk SHA3 into the chunk MAC, and the client learns it only by hashing
the received bytes. Verification is therefore whole-file granularity by
design, not a gap.

## What is built

- `rom_fetch_parse_directory` — bounded parser of the peer `/directory.json`
  `artifacts` array.
- `rom_fetch_chunk` / `rom_fetch_verify_file` / `rom_fetch_download` — one
  verified chunk fetch, a streaming verify pass, and the `.part`-stage →
  verify → atomic-rename driver.
- `rom_fetch_download_parallel` — bounded multi-seeder worker pool with a
  shared chunk queue and per-chunk round-robin retry across all peers.
- `ops.debug.rom_fetch.{status,bundle}` native commands
  (`engine/controllers/src/rom_fetch_controller.c`); `bundle` is owner-auth and
  takes the expected `(root, whole_sha3, size)` as explicit input.
- `dumpstate rom_fetch` state introspection.

## Open items

- **Resume** — per-chunk presence/SHA3 spot-check so an interrupted large
  fetch does not restart from zero.
- **Discovery mode** — pick up the manifest from `file_market` gossip offers
  or a peer's onion `/directory.json` instead of requiring explicit operator
  digests, while still committing the digest BEFORE fetching.
- **Live-network copy-prove** of a real bundle fetch against a seeding node,
  then the runbook line pairing `ops.debug.rom_fetch.bundle` with
  `-install-consensus-bundle` (see `FORWARD_PLAN.md` #1 item 1/4).
- **Keep-alive chunk streaming** (multiple `FS_REQUEST`s per connection) if
  profiling shows per-chunk handshake overhead matters at scale.

Out of scope for this engine: `core/chainparams/*` (checkpoint baking is a
separate concern — this engine takes the expected digest as input rather
than baking it), any change to the serve path, any install/activation call,
consensus validation semantics.
