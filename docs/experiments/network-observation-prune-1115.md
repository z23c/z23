<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
<!-- claim: symbol-present db_peer_chain_observation_prune engine/models/src/peer_chain_observation.c # retained observation pruning -->

# Peer observation prune diagnostics

On 2026-11-15, source base `d16b5a1ad53421746bd69cd829e8e3af21f0a01a` was tested with GCC 14.2.0 on an AMD Ryzen 9 7950X3D. The observation prune operation now reports the SQLite statement return code and its stable description when execution fails. It continues to return failure. This diagnostic does not repair database corruption.

An isolated database verified WAL mode, inserted 10,005 observations and retained 10,000. A query-only connection then caused the same prune to fail with `SQLITE_READONLY`; the fixture checked the reported code and description and that the retained count remained 10,000. Before the change, the focused test failed solely because the diagnostic was absent. After the change, `DEVBUILD_CLASS=normal devbuild --wait make -j28 t-fast ONLY=network_monitor` passed one group with no skips. The red log SHA-256 is `603f9904451c145ba33a22ba29046af7bf562d3a1c166ae986771cfa92f2f398`; the final passing log SHA-256 is `fbd491c8dbf485400f69df07106ee2440188960f1b5167c3754d1959750c409d`.

A boot-time check reported corruption in the observation table. The current live prune return code has not been observed; the fixture does not establish its cause or demonstrate a live repair.
