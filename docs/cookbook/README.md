<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Cookbook recipes

Numbered, runnable recipes for one task each: minting and spending, scripts,
tokens and names, swaps, reorg and adversary drills, a collectible market,
releases and a hosted onion app. Each recipe lists the exact commands and the
result to expect.

Commands: `discover.wiki`, `discover.read`

- List the recipes with summaries: `z23 wiki cookbook`.
- The overview and recipe order are in [`../dev/COOKBOOK.md`](../dev/COOKBOOK.md).

## Index

- [`01_mint_and_spend.md`](./01_mint_and_spend.md): Cookbook 01 — Mint and Spend
- [`02_multi_io_p2sh.md`](./02_multi_io_p2sh.md): Cookbook 02 — Multi-input/multi-output tx + P2SH spend
- [`03_op_return_overlay.md`](./03_op_return_overlay.md): 03_op_return_overlay
- [`04_zslp_token.md`](./04_zslp_token.md): 04 — ZSLP token lifecycle in the simulator
- [`05_znam_names.md`](./05_znam_names.md): 05 — ZNAM name registry lifecycle in the simulator
- [`06_htlc_swap.md`](./06_htlc_swap.md): 06 — HTLC atomic-swap contract lifecycle
- [`07_cluster_reorg.md`](./07_cluster_reorg.md): 07 — Multi-node cluster convergence (reorg)
- [`08_byzantine_blocks.md`](./08_byzantine_blocks.md): 08 — Byzantine blocks: adversarial input rejected by real consensus
- [`09_seed_replay.md`](./09_seed_replay.md): 09 — Seed Replay: Determinism as a Debugging Tool
- [`10_wire_adversaries.md`](./10_wire_adversaries.md): 10 — Wire adversaries: partition and heal a P2P link
- [`11_collectible_market.md`](./11_collectible_market.md): 11 — the full digital-collectible marketplace lifecycle
- [`12_sovereign_release.md`](./12_sovereign_release.md): 12_sovereign_release — your first chain-verified release in 5 minutes
- [`13_host_your_own_mvc_onion_app.md`](./13_host_your_own_mvc_onion_app.md): 13 — host your own MVC onion app
