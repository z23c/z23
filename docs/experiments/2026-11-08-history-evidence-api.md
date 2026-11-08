<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Retained history evidence

The archive validator rechecks selected ancestry and authenticates every selected block body. The caller separately admits the endpoint, verifies the complete manifest and keeps the archive immutable. The directory ancestry check assumes a stable trusted mount namespace and does not detect bind-mounted aliases. The artifact snapshot is an invalidation token from the retained descriptor, not content or pathname authority.

On 2026-11-08, the focused `wallet_history_export` and `consensus_state_snapshot_install` groups each passed with one group run and no skips on the reviewed six-file change. The fixtures accepted a valid archive, refused a changed block, checked the retained directory ancestry and invalidated the artifact token after replacement. These checks do not qualify a complete history provider or a production transfer.

```sh
devbuild --wait --class normal make t-fast-exact ONLY=wallet_history_export
devbuild --wait --class normal make t-fast-exact ONLY=consensus_state_snapshot_install
```

<!-- claim: symbol-present wallet_history_export_validate_archive engine/services/src/wallet_history_export.c # authenticated archive validation -->
<!-- claim: symbol-present wallet_history_export_parent_outside_source engine/services/src/wallet_history_export.c # retained directory ancestry check -->
<!-- claim: symbol-present consensus_state_artifact_evidence_snapshot engine/composition/src/consensus_state_snapshot_install.c # retained artifact identity -->
