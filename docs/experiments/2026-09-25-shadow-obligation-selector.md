<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Shadow proof-obligation selection

Measured 2026-09-25 on an AMD Ryzen 9 7950X3D (32 logical CPUs) with GCC
14.2.0. The base is `52bee3bb8c719de149512ea9fdebe94b239cdf2a`. The code
is on branch `lane/muse-shadow-select-20260925`.

This is a shadow experiment and it changes nothing about acceptance. Landing
proofs still run every lint gate and every test group their own selector
names. The code only reports what a narrower selector would have run, what
that would cost, and which of its skips a checked rule could defend.

## Standing and qualification

**A passing corpus is not a soundness argument.** Zero RED on 28 entries
shows only that none of these 28 changes, with these seeded bugs, found a
hole. It does not show that the prediction is a superset of the required
obligations for every change. Mandatory acceptance (all lint gates plus the
landing selector's groups, run fresh) stays in force.

Qualifying the rule for use in admission would need at least the following:

1. **A proof that the reverse-caller and reverse-include closure is
   complete for every premise class.** That includes calls through function
   pointers and registries, `extern` declarations without a header,
   generated headers, and negative lookups. Today the depfile and the
   codeindex cannot see a header that does not exist yet (see
   syn-negative-lookup).
2. **A contract root computed from exact header bytes and declared
   premises.** The token-normalized root used here is an approximation. It
   should be derived by the proof-ticket library, or by
   `zcl.proof_frontier.v1` once that exists, so that a macro, a layout or
   an assertion cannot move without moving the root.
3. **A component lookup key that binds every execution input separately.**
   The key must cover unit, dependency closure, negative lookups, generated
   inputs, ABI generation, fixtures, invariants and integration edges (see
   "Missing key inputs"). A carried verdict is receivable only when every
   input matches.
4. **Independent, signed caller verdicts.** A verdict written by the
   candidate's own uid is writable by the candidate, so under the fail-closed
   same-uid decision it is never eligible.
5. **A mutation campaign much larger than this corpus, run against the full
   reference and not a bounded one.** Every seeded bug caught by a skipped
   obligation must become a regression test.
6. **An independent review of `zcl_shadow_reuse_admit()` and
   `zcl_shadow_reuse_eligible()`.** Each condition in them must already have
   a refusal test (tests/harness/src/test_dev_shadow_select.c).

## What runs

The whole report comes from one test group,
`make t-fast ONLY=test_dev_shadow_select`. For each frozen corpus entry it
does the following:

- It reproduces the landing selector with the calls dev proof uses:
  `zcl_devloop_plan_files` → `zcl_devloop_plan_add_closure` →
  `zcl_devloop_plan_proof_admissible`, with families expanded via
  `zcl_test_group_family_expand`. A universal or refused plan becomes the
  whole host-admitted catalog.
- The reference is the full landing proof: all 213 lint gates plus every
  host-admitted test group. `check-windows-cross-syntax` is counted at full
  cost, and lint premise selection is out of scope.
- It builds a proof dependency graph that is kept apart from build
  dependencies. The graph has three layers:
  - CONTRACT: the groups the changed files name through the impact rules;
  - CALLER: groups reached by reverse-caller or reverse-include closure
    inside the component, or by an opaque rule;
  - INTEGRATION: groups reached through another component's file.
- It writes the prediction (`predicted.tsv`) before any reference run, and
  compares it with the reference run (`observed.tsv`).

Every obligation is classified in one of two ways:

- **source-sensitive**: the lint gates. These always rerun when a source
  they read changes.
- **image-sensitive**: the test groups. An unchanged output artifact may stop
  propagation to them. It never waives a source gate.

The prediction has three cases:

- **ALL** (the reference) when any fallback reason fires. The reasons are
  conflict, policy, dependency-change and unknown-scope.
- **The contract layer only** when the compositional rule holds: the
  contract root is unchanged, no other TU reads a changed private file, and
  the build graph is known. Callers and integration edges are carried.
- **Every selected group** otherwise.

Lint gates are always fresh.

The compositional rule (`zcl_shadow_reuse_admit`) needs three things: an
unchanged contract root, a fresh PASS of the callee's contract obligations
on exactly the new implementation root, and caller premises that reference
only the contract. An unchanged ABI or an old PASS is not an input to the
rule. The test "unchanged ABI with an old PASS never admits reuse" pins that.

## Measured numbers

Report from `test_dev_shadow_select` at head `16655819e6`, rebased onto
`52bee3bb8c`. That run was a PASS with 0 skipped. Seconds are
cost-weighted fresh worker CPU.

| set | fresh obligations | fresh s/candidate: rule | landing selector | reference | savings (rule) | savings (selector) | critical path s (rule / reference) | validation s |
|---|---|---|---|---|---|---|---|---|
| real (20 narrow commits) | 6030 / 28120 | 2082.3 | 2456.0 | 6402.1 | 67.5% | 61.6% | 134.0 / 257.9 | 1.21 |
| synthetic (8) | 10072 / 11248 | 5804.4 | 2312.0 | 6402.1 | 9.3% | 63.9% | 241.6 / 257.9 | 0.16 |
| all (28) | 16102 / 39368 | 3145.7 | 2414.9 | 6402.1 | 50.9% | 62.3% | 164.7 / 257.9 | 0.91 |

**Totals: 3145.7 fresh worker-seconds per candidate for the rule and
2414.9 for the landing selector, against 6402.1 for the reference.** The
landing selector is cheaper than the rule only because it expands no
fallback. It is also the predictor with five false hits (see below).

**Savings that are eligible today are zero.** Every carried obligation is
refused as `execution_inputs_incomplete`: the lookup key omits unit and
dependency closure. With a complete key the same obligations would still
be refused as `same_uid_local_verdict`. The only verdicts a host holds are
its own uid's, and under the fail-closed decision those never stand in for
a run. So the eligible-now bill equals the reference, 6402.1 s per
candidate. The 67.5% figure on narrow edits is the ceiling that
independent signed verdicts plus a complete key would allow. It is not a
saving available now. No hit-rate target is set.

Where the rule's remaining fresh bill goes on the 20 narrow commits,
largest first:

| obligation class | fresh s (20 entries) | share of reference |
|---|---|---|
| lint gates (source-sensitive, always fresh) | 23231.1 | 18.1% |
| contract layer of the changed unit | 8081.8 | 6.3% |
| fallback to reference (real-18, `unmapped-code-change`) | 5240.6 | 4.1% |
| additive contract or private reader, selected set kept (real-03, -12, -14, -19) | 5091.6 | 4.0% |

The contract layer includes the 13-group `make_lint_gates` family, which
the impact rules attach to every C change: about 328 s per candidate. Lint
premise selection is out of scope here; `check-windows-cross-syntax` is
being made reusable in a separate lane and is counted at full cost.

Per entry. Obligations are 213 lint gates plus 1193 host-admitted test
groups; seconds are per candidate:

| entry | kind | contract | fallback | predict | fresh / total | rule s | selector s | reference s | savings (rule) | critical path s (rule / reference) | name-only s |
|---|---|---|---|---|---|---|---|---|---|---|---|
| real-01 | real | none | none | exact | 239/1406 | 1954 | 2012 | 6402 | 69.5% | 128 / 258 | 0 |
| real-02 | real | none | none | exact | 242/1406 | 2054 | 2054 | 6402 | 67.9% | 128 / 258 | 0 |
| real-03 | real | additive | none | exact | 256/1406 | 2127 | 2127 | 6402 | 66.8% | 128 / 258 | 0 |
| real-04 | real | none | none | exact | 234/1406 | 1519 | 3622 | 6402 | 76.3% | 128 / 258 | 2103 |
| real-05 | real | none | none | exact | 231/1406 | 1633 | 1659 | 6402 | 74.5% | 128 / 258 | 26 |
| real-06 | real | none | none | exact | 232/1406 | 1634 | 2466 | 6402 | 74.5% | 128 / 258 | 26 |
| real-07 | real | none | none | exact | 232/1406 | 1644 | 2266 | 6402 | 74.3% | 128 / 258 | 52 |
| real-08 | real | none | none | exact | 241/1406 | 1980 | 2254 | 6402 | 69.1% | 128 / 258 | 0 |
| real-09 | real | none | none | exact | 234/1406 | 1692 | 1718 | 6402 | 73.6% | 128 / 258 | 26 |
| real-10 | real | none | none | exact | 230/1406 | 1522 | 2409 | 6402 | 76.2% | 128 / 258 | 26 |
| real-11 | real | none | none | exact | 230/1406 | 1522 | 2409 | 6402 | 76.2% | 128 / 258 | 26 |
| real-12 | real | additive | none | exact | 300/1406 | 2823 | 2823 | 6402 | 55.9% | 128 / 258 | 44 |
| real-13 | real | none | none | exact | 235/1406 | 1709 | 2213 | 6402 | 73.3% | 128 / 258 | 0 |
| real-14 | real | additive | none | exact | 260/1406 | 2430 | 2430 | 6402 | 62.0% | 128 / 258 | 26 |
| real-15 | real | none | none | exact | 235/1406 | 1709 | 2247 | 6402 | 73.3% | 128 / 258 | 0 |
| real-16 | real | none | none | exact | 239/1406 | 1954 | 2079 | 6402 | 69.5% | 128 / 258 | 0 |
| real-17 | real | none | none | exact | 226/1406 | 1489 | 2085 | 6402 | 76.7% | 128 / 258 | 596 |
| real-18 | real | none | unknown-scope | all | 1406/1406 | 6402 | 6402 | 6402 | 0.0% | 258 / 258 | 0 |
| real-19 | real | additive | none | exact | 302/1406 | 2358 | 2358 | 6402 | 63.2% | 128 / 258 | 28 |
| real-20 | real | none | none | exact | 226/1406 | 1489 | 1489 | 6402 | 76.7% | 128 / 258 | 0 |
| syn-header-decl | header_decl | moved | unknown-scope | all | 1406/1406 | 6402 | 1861 | 6402 | 0.0% | 258 / 258 | 26 |
| syn-abi | abi | moved | unknown-scope | all | 1406/1406 | 6402 | 1861 | 6402 | 0.0% | 258 / 258 | 26 |
| syn-flag | flag | none | dependency-change | all | 1406/1406 | 6402 | 1489 | 6402 | 0.0% | 258 / 258 | 0 |
| syn-contract | contract | moved | unknown-scope | all | 1406/1406 | 6402 | 1861 | 6402 | 0.0% | 258 / 258 | 26 |
| syn-private-impl | private_impl | none | none | exact | 230/1406 | 1621 | 1861 | 6402 | 74.7% | 128 / 258 | 26 |
| syn-generated-input | generated_input | none | dependency-change | all | 1406/1406 | 6402 | 6402 | 6402 | 0.0% | 258 / 258 | 0 |
| syn-negative-lookup | negative_lookup | none | unknown-scope | all | 1406/1406 | 6402 | 1633 | 6402 | 0.0% | 258 / 258 | 0 |
| syn-macro | macro | moved | unknown-scope | all | 1406/1406 | 6402 | 1527 | 6402 | 0.0% | 258 / 258 | 0 |

## Obligations predicted fresh

This is the hand-off list: exactly what the rule would run fresh, with the
reason for each layer. The reason `contract_obligation_of_changed_unit`
marks the unit's own contract obligations. `contract_additive` marks a
contract that grew, so the selector's callers and integration edges are
kept. None of these groups is carried as eligible today (see above).

Every entry: all 213 lint gates are predicted fresh (reason:
source-sensitive, changed source always reruns).

Entries predicted ALL run the whole host-admitted catalog of 1193 groups,
for the fallback reason in the table above.

Exact entries run the test groups below:

- **real-01** (contract, contract_obligation_of_changed_unit): hotswap_simnet, hotswap_module_v2, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, native_api_contract, make_lint_gates, vcs_devloop, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-02** (contract, contract_obligation_of_changed_unit): hotswap_simnet, hotswap_module_v2, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, impact_composition, dev_proof_signer, command_registry_catalog, native_api_contract, make_lint_gates, vcs_devloop, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-03** (contract, contract_obligation_of_changed_unit): mind, code_capsule, code_impact, hotswap_module, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, command_registry_catalog, command_registry_latency, native_api_contract, command_handler_snapshot, make_lint_gates, codeindex, codeindex_scale, code_firsthour, code_fetch, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-03** (caller, contract_additive): code_merkle, code_merkle_proof, code_emitter, blocker, testcache
- **real-03** (integration, contract_additive): code_inventory, chainlog, code_growth, science
- **real-04** (contract, contract_obligation_of_changed_unit): hotswap_loader, hotswap_simnet, hotswap_module, hotswap_module_v2, binary_ab_fallback, make_lint_gates, group_selector, boot_shutdown_marker, self_backtrace, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-05** (contract, contract_obligation_of_changed_unit): zcode_package_registry, make_lint_gates, event_log, vcs_core, package_capability_claim, zcode_swarm_net, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-06** (contract, contract_obligation_of_changed_unit): zcode_package_registry, make_lint_gates, event_log, vcs_core, zcode_swarm, zcode_swarm_net, zcode_swarm_complete, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-07** (contract, contract_obligation_of_changed_unit): zcode_package_registry, make_lint_gates, event_log, vcs_core, zcode_verify, zcode_attransport, zcode_swarm_net, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-08** (contract, contract_obligation_of_changed_unit): hotswap_simnet, hotswap_module_v2, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, native_api_contract, make_lint_gates, vcs_devloop, group_selector, boot_shutdown_marker, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-09** (contract, contract_obligation_of_changed_unit): zcode_package_registry, db_migration_idempotent, make_lint_gates, os_sandbox, sandbox_process_budget, zcode_dev_objects, build_fabric, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02, resident_launch, resident_launch_contract
- **real-10** (contract, contract_obligation_of_changed_unit): command_registry_catalog, native_api_contract, make_lint_gates, zcode_verify, zcode_add, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-11** (contract, contract_obligation_of_changed_unit): command_registry_catalog, native_api_contract, make_lint_gates, zcode_verify, zcode_add, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-12** (contract, contract_obligation_of_changed_unit): zcode_package_registry, command_registry_catalog, make_lint_gates, event_log, vcs_core, zcode_public_shape, zcode_swarm_net, zcode_dev_objects, vcs_devloop, golden_revert_roundtrip, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-12** (caller, contract_additive): dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, story_graph, build_fabric
- **real-12** (integration, contract_additive): qr, engine, engine_rules, zid_seniority, robustness, wallet, shop_want, shop_fulfill, cold_join_sovereign, file_controller, rom_seed, rom_fetch, source_bundle_fetch, source_bundle_publish, spawn, integrity, hotswap_module, hotswap_service_registry, impact_composition, dev_activation, metaverse_agent_broker, metaverse_vocabulary, metaverse_broker_authority, native_api_contract, command_handler_snapshot, binary_ab_fallback, network_monitor, cli_argv_strict, condition_engine, blocker, zcode_store, zcode_publish, zcode_package_dev, zcode_verify, zcode_attransport, zcode_dht_service, zcode_badge, zcode_fetch, zcode_add, dev_land, group_selector, metaverse_catalog, site_routes, golden_dev_cycle, utxo_apply_stage, read_leaf_no_datadir_write, boot_shutdown_marker, zswap_quote, zswap_yardsale, zswap_ceremony, syncdiag_rpc, thread_qos, block_prefetch, agent_spend_policy
- **real-13** (contract, contract_obligation_of_changed_unit): zcode_package_registry, make_lint_gates, event_log, vcs_core, zcode_verify, zcode_public_shape, zcode_swarm_net, zcode_dev_objects, story_graph, build_fabric, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-14** (contract, contract_obligation_of_changed_unit): zcode_package_registry, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, make_lint_gates, event_log, vcs_core, zcode_swarm_net, vcs_devloop, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-14** (integration, contract_additive): hotswap_module, hotswap_service_registry, impact_composition, dev_activation, command_registry_catalog, native_api_contract, command_handler_snapshot, zcode_package_dev, zcode_verify, zcode_commons, zcode_public_shape, zcode_dev_objects, story_graph, group_selector, golden_revert_roundtrip, golden_dev_cycle, boot_shutdown_marker, vault_read, vault_dispatch, build_fabric
- **real-15** (contract, contract_obligation_of_changed_unit): zcode_package_registry, make_lint_gates, event_log, vcs_core, zcode_verify, zcode_public_shape, zcode_swarm_net, zcode_dev_objects, story_graph, build_fabric, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-16** (contract, contract_obligation_of_changed_unit): hotswap_simnet, hotswap_module_v2, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, native_api_contract, make_lint_gates, vcs_devloop, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-17** (contract, contract_obligation_of_changed_unit): make_lint_gates, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-19** (contract, contract_obligation_of_changed_unit): rpc, chain_evidence_controller, chain_evidence_live_advance, command_registry_catalog, make_lint_gates, supervisor, syncdiag_rpc, debug_bundle, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-19** (caller, contract_additive): rom_seed, rom_fetch, rom_fetch_onion, source_bundle_fetch, source_bundle_publish, rom_manifest, rom_journal_resume, hotswap_loader, native_api_contract, sysinit, supervisor_backstop, sd_notify, chain_tip_watchdog_bounded_restart, os_sandbox, operator_ux
- **real-19** (integration, contract_additive): net, sqlite, models, file_market, api, mesh_pairing, mesh_status_proto, mesh_status_wire, node_health_service, sync_service, snapshot_sync_service, snapshot_serve_loopback, file_controller, file_service_pow_gate, code_capsule, code_emitter, hotswap_module, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, command_registry_latency, command_handler_snapshot, dbquery_secret_denylist, db_maintenance, header_sync, header_sync_stall, db_migration_idempotent, msg_handlers, net_handshake_adversarial, condition_engine, blocker, boot_mesh_terminal, mesh_terminal_client, mesh_stream, body_persist_stage, zcode_store, zcode_dht_service, offline_datadir_query, db_maintenance_port, peer_lifecycle, telemetry_ontology, telemetry_storage, reducer_forward_progress_gate, stopwatch_skip_watch, slo_ledger_summary, tip_agreement_watch, health_rollup, command_input_bounds
- **real-20** (contract, contract_obligation_of_changed_unit): make_lint_gates, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **syn-private-impl** (contract, contract_obligation_of_changed_unit): byte_order_codec, codec_cursor, zcode_package_registry, make_lint_gates, zcode_swarm_net, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02

## Proof premises versus build dependencies

Build dependencies are the TUs that recompile. Proof premises are what an
obligation's verdict depends on. The two diverge in both directions:

- **Premise outside the depfile.** syn-negative-lookup invalidates 0 of
  8315 build actions by the depfile graph, yet the new
  `contexts/commons/modules/vcs/src/codec/cursor.h` captures <!-- doc-path-ok: created only by the syn-negative-lookup patch -->
  `#include "codec/cursor.h"` for 34 vcs sources. A dry run of
  `make t-fast-exact` recompiled none of them, so incremental make links
  stale objects unless those sources are touched.
  syn-generated-input also invalidates 0 build actions by depfile, while the
  generator rewrites `install_script_gen.h`.
- **Build wider than premise.** For private edits (syn-private-impl,
  real-17) one TU recompiles, but the selector reruns 38 and 54 groups. The
  premises that actually moved are the 17 and 13 contract-layer groups.
- **Global premise.** syn-flag rebuilds all 8315 TUs: the Makefile is a
  build-graph input. The proof premise that moved, the `-DZCL_DEV_BUILD`
  gate in `hotswap_activate.o`, reaches only the hotswap groups, and the
  landing selector names none of them.
- **Name-only caller hops.** `codeindex_callers()` matches callees by bare
  name. Across all 28 entries, 235 selected groups (3081.9 s; 227 and
  2978.1 s on the real set) were reached only through a
  reverse-caller hop whose TU reads no header of any component the walk
  reached legitimately. real-04 alone accounts for 151 groups and 2102.6 s,
  real-17 for 41 groups and 595.6 s. This is reported as an
  over-approximation, not fixed; the code-index owner has it.

## False-hit witnesses

Each synthetic entry was reference-run under its patch with
`make t-fast-exact ONLY=<bounded set> T_FAST_EXACT_ARGS=--no-cache`,
touching every reader so that no stale object was reused. This ran after
`predicted.tsv` was committed (git order: 25aebccc04 then
8c49b46d1f). The frozen predictions were generated by 1079c9fb7c, which was 0016cffa9e before the rebase, and are
never regenerated. The
bound is the landing selector's groups plus candidate groups named by
grepping callers; it is not the full catalog.

| entry | seeded bug | failing groups | landing selector | frozen rule prediction |
|---|---|---|---|---|
| syn-private-impl | payload length equal to capacity refused | zcode_package_registry, zcode_swarm_net | covered | covered (contract layer) |
| syn-header-decl | `finish` stops flagging trailing bytes | codec_cursor, zcode_package_registry, zcode_swarm_net | covered | covered |
| syn-abi | reader fields reordered, length narrowed to 16 bits | zcode_package_registry, zcode_swarm_net, zcode_dev_objects | covered | covered |
| syn-macro | `ASTRO_YEAR_MAX` 9999 → 8999 | node_character_wire | covered | covered |
| syn-contract | `finish` accepts trailing bytes; callee test rewritten to agree | zcode_package_registry, zcode_swarm_net, story_graph, **zcode_recipe** | **MISS zcode_recipe** | **RED: zcode_recipe** |
| syn-negative-lookup | shadow header maps `finish` to a trailing-tolerant shim | zcode_package_registry, **zcode_recipe** | **MISS zcode_recipe** | covered (ALL) |
| syn-flag | `-DZCL_DEV_BUILD` dropped from `hotswap_activate.o` | **hotswap_module, hotswap_shelf, hotswap_rollback** | **MISS all three** | covered (ALL) |
| syn-generated-input | install script pin quoted with `'` | install_sh_site | covered (universal) | covered (ALL) |

What the witnesses show:

1. **One RED against the frozen prediction: syn-contract / zcode_recipe.**
   The contract moved, so the rule predicted the selector's own set. The
   recipe decoder reaches `zcl_codec_reader_finish` through
   `package_recipe.c`, a proof-owner file where the caller closure stops. The
   fix is that a moved contract now predicts the reference (`unknown-scope`).
   The test pins the frozen RED (`frozen_rule=1`,
   `syn-contract:test_zcode_recipe`) and requires `live_rule=0`.
2. **Five landing-selector false hits:**
   - zcode_recipe under syn-contract and under syn-negative-lookup;
   - hotswap_module, hotswap_shelf and hotswap_rollback under syn-flag.

   Any of these bugs would land under today's selector. The test pins
   `frozen_selector=5`.
3. **The compositional rule's premise is weaker than it looks
   (syn-private-impl).** The callee's own contract test, `codec_cursor`,
   PASSED on the buggy implementation. The two callers that caught the bug
   were covered only because the impact rules attach them to `codec/`
   directly. An "own contract tests passed fresh" condition proves only what
   those tests assert. That is why qualification item 2 asks for a contract
   root over declared premises and not over tests alone.
4. **Unchanged ABI is not enough (syn-contract).** Every declaration and
   layout is byte-identical, yet four groups fail.
   `zcl_shadow_reuse_admit` never takes ABI equality as an input, and its
   test refuses an unchanged ABI with an old PASS.

## Largest avoidable rerun

real-04, a change to a test file in `tests/harness`. The landing selector
runs 172 groups (3622 s). 151 of them, 2102.6 s, were reached only through
name-only caller hops. The rule would keep the 21 contract-layer groups.
That rerun is avoidable once caller lookup is symbol-exact: F1's frontier
seeds from changed functions and routes around the name collision.

## Missing key inputs

The fields that `zcl.zcode.component_input_key.v1`
(`contexts/commons/modules/vcs/include/vcs/zcode_action_input.h`) does not
bind separately, compared with the 19 fields of the proof-ticket branch's
`zcl.component_proof_key.v1`. Ranked by the reference cost above what the
rule would still run on the entries whose premises moved them:

| missing input | entries | broad invalidation (s) |
|---|---|---|
| **unit_id**: the key folds the whole candidate source tree into `candidate_source_root`, so any byte anywhere changes every key | 26 | 91178.8 |
| **dependency_closure**: no per-component closure root, so a callee edit cannot be told apart from an unrelated one | 21 | 81917.4 |
| integration_edges: no binding of which consumer edge a verdict covers | 8 | 15870.7 |
| abi_generation, invariants | 4 | 0 (these entries now fall back to the reference) |
| negative_lookups: a header that did not exist cannot appear in any root | 1 | 0 (falls back) |
| generated_inputs: generator input bytes are only inside the whole tree | 1 | 0 (falls back) |

The key also lacks linker, sysroot and fixtures as separate roots. These
fields are why every carried verdict is `execution_inputs_incomplete`:
unit_id and dependency_closure cause the most broad invalidation, and
negative_lookups and generated_inputs cause the unknown-scope fallbacks.

## Cost weights

The weights are in `tools/dev/fixtures/shadow_select/weights.tsv`. Each
weight is the mean of fresh (uncached) service milliseconds per obligation
from `costs.tsv`: 125,749 rows from 485 landing-proof attempt logs, sha256
`3b8b7a8b175830c915d17aa6d8c39283d1ef5bcd37ea258a4b3d150fc512d126`. A
group with no measurement is priced at the median group weight and counted
in `unweighted=`.

Validation overhead is measured, not assumed. For each carried obligation,
the per-obligation cost is 19 field SHA3 roots, a 624-byte preimage SHA3,
a 360-byte ticket SHA3 and one Ed25519 verification.

## Unfinished

- **Second predictor column (function-granular frontier F1, branch
  `frontier/symbol-seeds` at 427f6dba3f).** It is not computed. It needs a
  separate build of that tree with these files, plus the pre- and post-patch
  bytes of each changed file, fed through `zcl_frontier_dir_read` into
  `plan->frontier`. The predict step takes a tree root, so it can be rerun
  once F1 and the catalog mask are on main.
- **The reference runs are bounded.** Each covers the selector's groups plus
  the named candidate groups, not the whole catalog, so a RED outside that
  bound would go unseen.
