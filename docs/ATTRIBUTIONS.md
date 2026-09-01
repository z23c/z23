# Attributions

z23 is licensed under the **Apache License, Version 2.0** (see
[`LICENSE`](../LICENSE)). Upstream copyright notices from inherited code
and vendored dependencies are preserved in [`NOTICE`](../NOTICE) as
required by Apache 2.0 §4(d).

This file documents **concepts and architectural patterns** (not
verbatim source code) that z23 has adopted from other
projects. We credit them here because it is the right thing to do —
all ideas listed below are re-implemented in C23 from scratch and do
not link against the original code. Apache 2.0 is compatible with
the licenses of every project listed here per the Free Software
Foundation's compatibility matrix.

If you are reading this and recognize a pattern we've ported without
naming you here, open a PR or ping the maintainers and we'll add you.

---

## Erigon — Ethereum execution client, LGPL-3.0

**Repository:** https://github.com/erigontech/erigon
**License:** [GNU LGPL-3.0](https://github.com/erigontech/erigon/blob/main/COPYING.LESSER)
**Attribution:** Copyright © The Erigon Authors

Concepts we've adopted:

| z23 feature | Erigon source referenced | Notes |
|---|---|---|
| `struct zcl_stage` + staged sync runner | [`execution/stagedsync/stage.go`](https://github.com/erigontech/erigon/blob/main/execution/stagedsync/stage.go), [`sync.go`](https://github.com/erigontech/erigon/blob/main/execution/stagedsync/sync.go) | Forward/Unwind/Prune triad per stage |
| Stage pipeline ordering | [`default_stages.go`](https://github.com/erigontech/erigon/blob/main/execution/stagedsync/default_stages.go) | Explicit forward vs unwind order |
| Per-stage `Cfg` struct pattern | `HeadersCfg` / `ExecuteBlockCfg` | One config struct per stage |
| ETL (Extract-Transform-Load) for bulk writes | [`db/etl/README.md`](https://github.com/erigontech/erigon/blob/main/db/etl/README.md) | Temp-file sort before bulk load to minimize write amplification |
| Temporal DB interface (hot mutable + cold immutable) | [`db/kv/kv_interface.go`](https://github.com/erigontech/erigon/blob/main/db/kv/kv_interface.go), [`db/agents.md`](https://github.com/erigontech/erigon/blob/main/db/agents.md) | `get_latest(k)` + `get_as_of(k, ts)` |
| Stream vs Cursor split | `db/kv/stream/`, cursor interfaces in `kv_interface.go` | High-level iterator over low-level cursor |
| Per-subsystem `agents.md` files | [`execution/stagedsync/agents.md`](https://github.com/erigontech/erigon/blob/main/execution/stagedsync/agents.md), `cl/agents.md`, `p2p/agents.md`, `db/agents.md` | Localized AI guidance close to code | <!-- doc-path-ok: upstream erigon paths, not this tree -->
| Explicit naming discipline at the top of storage headers | [`kv_interface.go:30-50`](https://github.com/erigontech/erigon/blob/main/db/kv/kv_interface.go) naming block | `tx` vs `txn`, `blockNum` vs `blockID`, etc. |
| Per-stage timing table | `sync.go::timings` | Wall-clock per stage, dumped on cycle end |
| Ruleguard-style antipattern lint | Erigon `CLAUDE.md` ("defer tx.Rollback after error check") | Pattern-level grep gates per recurring issue |
| Consensus spectest harness | [`cl/spectest/`](https://github.com/erigontech/erigon/tree/main/cl/spectest) | Reference corpus → replay → diff state |

These patterns are cited inline in the per-subsystem `agents.md`
files as they land.

---

## Bitcoin Core — MIT

**Repository:** https://github.com/bitcoin/bitcoin
**License:** MIT

The consensus surface of this project descends from Bitcoin Core via
zcashd via zclassicd. Core-inherited algorithms (script interpreter,
BIP-30 / BIP-34 / BIP-65 / BIP-66 semantics, Bloom filter, compact
blocks) are MIT-licensed at their root.

## zcashd — MIT

**Repository:** https://github.com/zcash/zcash
**License:** MIT

Sapling and Sprout zk-SNARK designs, Equihash 200/9 PoW, and the
shielded-pool accounting rules.

## zclassicd (legacy peer) — MIT

**Repository:** https://github.com/ZclassicCommunity/zclassic
**License:** MIT

Chain history, checkpoint schedule, network magic, and the reference
behavior used by the z23 parity-diff service.

## dcrdex — Blue Oak Model License 1.0.0 (concept reference)

**Upstream:** https://github.com/decred/dcrdex
**License:** https://blueoakcouncil.org/license/1.0.0

The cross-chain atomic-swap HTLC script format (P2SH-wrapped, 97-byte contract)
used by the ZCL atomic-swap protocol (ZSWP) was **reimplemented** from dcrdex's
design in `core/modules/script/` (`core/modules/script/{src/htlc.c,include/script/htlc.h}`) — no dcrdex source is vendored in this
tree. Credited here for the script-format concept.

## SQLite — Public Domain

**Vendored path:** `vendor/` amalgamation
**License:** https://www.sqlite.org/copyright.html

Embedded database for the canonical UTXO store, wallet keystore, block
index (with CRC), and application state.

## RGFW 1.8.1 — zlib License

**Repository:** https://github.com/ColleagueRiley/RGFW
**Pinned revision:** `d96684e6877d3ef11c731b122b8949942ed071c9`
**Vendored path:** `vendor/rgfw/`
**Attribution:** Copyright © 2022-2025 Riley Mabb (@ColleagueRiley)

The private software-window backend for `contexts/explorer/modules/presentation`. Z23 exposes
its own bounded bitmap ABI; no RGFW type crosses the public boundary.

## X.Org client headers — X.Org MIT License

**Source:** https://xorg.freedesktop.org/releases/individual/lib/ +
https://xorg.freedesktop.org/releases/individual/proto/ (verbatim headers as
packaged by Ubuntu 24.04 `libx11-dev` 2:1.8.7-1build1 + `x11proto-dev`
2023.2-1)
**Vendored path:** `vendor/x11/`
**Attribution:** Copyright © the X.Org Foundation and contributors (see
`vendor/x11/LICENSE` for the canonical X.Org permission notice)

The 17 compile-time headers RGFW's Linux backend `#include`s. X11 itself is
loaded at runtime by the vendored XDL layer — these headers exist so a
headless host with no system `-dev` packages still builds the full binary.

## QR Code generator 1.8.0 — MIT

**Repository:** https://github.com/nayuki/QR-Code-generator
**Pinned revision:** `720f62bddb7226106071d4728c292cb1df519ceb`
**Vendored path:** `vendor/qrcodegen/`
**Attribution:** Copyright © Project Nayuki

The dependency-free QR Model 2 encoder behind `platform/modules/encoding/qr`.

## System Reference Document 5.1 — CC BY 4.0

**Source:** https://dnd.wizards.com/resources/systems-reference-document
**License:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/legalcode)
**Attribution:** © Wizards of the Coast LLC

> This work includes material taken from the System Reference Document 5.1
> ("SRD 5.1") by Wizards of the Coast LLC and available at
> https://dnd.wizards.com/resources/systems-reference-document. The SRD 5.1 is
> licensed under the Creative Commons Attribution 4.0 International License
> available at https://creativecommons.org/licenses/by/4.0/legalcode.

Used by `contexts/commons/modules/metaverse/` (`character_sheet.h`, `character_sheet.c`), and this
is the complete list:

| SRD 5.1 material | Where it is used |
|---|---|
| The six ability names — Strength, Dexterity, Constitution, Intelligence, Wisdom, Charisma | `enum character_attribute` and `character_attribute_name()` |
| The ability modifier rule, floor((score − 10) / 2) | `character_ability_modifier()` |
| The standard array's point total, 72 (15+14+13+12+10+8) | `CHARACTER_ATTRIBUTE_TOTAL`, the fixed total every character shares |

No Product Identity is used: no class, monster, spell, deity, setting, or
proper name from any non-SRD source appears in this tree, and the same
restraint binds anything that extends the module.

## ZClassic logo — CC BY 4.0

**Source:** https://commons.wikimedia.org/wiki/File:ZClassic_Logo.svg
**Attribution:** @jojo, ZClassic Slack/Rocket.Chat, 2016-12-05

`contexts/explorer/modules/presentation/src/zclassic_icon_mask.inc` is a 64px one-bit rasterization
of the official mark. The shape and canonical `#C87035` color are unchanged.

## stb_truetype — MIT or Public Domain

**Repository:** https://github.com/nothings/stb
**Pinned revision:** `2c980bb59875b0d32144a71867fbdebb2f77cd20`
**Attribution:** Copyright © 2017 Sean Barrett

The private antialiased font rasterizer behind the presentation canvas.

## Noto Sans Basic Latin subset — SIL OFL 1.1

**Repository:** https://github.com/notofonts/noto-fonts
**Pinned revision:** `ffebf8c1ee449e544955a7e813c54f9b73848eac`
**Attribution:** Copyright 2018 The Noto Project Authors

The embedded Basic Latin font bytes behind dependency-free presentation text.
The full upstream font is subset during vendoring; the exact recipe and both
source/subset hashes are recorded in `vendor/typography/SOURCE`.

## AGENTS.md portable-standard (community convention) — no license

**Reference:** https://www.augmentcode.com/guides/how-to-build-agents-md,
https://github.com/0xdevalias/some-notes-on-ai-rule-files

Emerging 2026 convention for AI coding agents: `AGENTS.md` at repo
root is the portable successor to per-tool files (`.cursorrules`,
`CLAUDE.md`, etc.). z23 adopts the convention with a dual-link
to `CLAUDE.md` for Claude Code compatibility.

## Codified Context Infrastructure (arxiv 2602.20478)

**Reference:** https://arxiv.org/abs/2602.20478

Three-tier pattern for AI-native codebases: (1) hot-memory constitution
(conventions + retrieval hooks), (2) specialized domain-expert agents,
(3) cold-memory knowledge base of specification documents. Used for
the cold-memory spec corpus in `docs/spec/`.

## Tor (modified fork with dynhost) — 3-clause BSD

**Vendored path:** `vendor/tor`
**License:** https://gitlab.torproject.org/tpo/core/tor/-/blob/main/LICENSE

Embedded Tor with in-process dynhost API for .onion hidden service
hosting. Fork maintained at https://github.com/RhettCreighton/tor.
