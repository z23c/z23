<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Android home startup status

The built-in home puts node status before Wallet and Receive. More holds secondary actions and the node control. During startup, a stage is shown only for the current managed process while its log reader is active; replay progress takes precedence.

<!-- claim: symbol-present zapp_node_boot_stage apps/z23android/operations.c # startup stage identity guard -->

Focused host tests passed for home layout, log stage classification, process identity and stop guards. The Android native target compiled successfully. Phone navigation, text sizing and startup timing were not measured for this change.
