#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_before_save_hooks.sh — critical models must WIRE before_save hooks
# (Makefile `check-before-save-hooks` gate): each of utxo/block/wallet_tx must
# contain an ar_register_before_save(...) call (a bare 'before_save' comment
# does not count). wallet_key is NOT in that list: it has no AR save by design
# (single-writer doctrine — wallet_sqlite owns the wallet key/seed secret
# columns), and the gate instead ratchets that the plaintext model saves
# never return. Extracted verbatim from the former inline Makefile recipe
# for tools/lint/run_lint.sh + standalone use.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

for model_path in engine/models/src/utxo.c engine/models/src/block.c \
                  contexts/wallet/models/src/wallet_tx.c; do
    f="$model_path"
    test -f "$f" \
    || { echo "FAIL: $f missing (model file moved/renamed)"; exit 1; }
    grep -qE 'ar_register_before_save[[:space:]]*\(' "$f" \
    || { echo "FAIL: $f does not WIRE a before_save hook (no ar_register_before_save(...) call; a bare 'before_save' comment does not count)"; exit 1; }
done

# wallet_key is deliberately NOT in the hook list above: the model has no
# AR save at all. Single-writer doctrine — the encryption-aware
# wallet_sqlite layer is the ONLY writer of the wallet_keys /
# wallet_sapling_keys / wallet_seed secret columns (the plaintext model
# saves and their "passphrase_set_pending_encryption" hooks were removed).
# Ratchet the invariant: the plaintext writers must never come back.
f=contexts/wallet/models/src/wallet_key.c
test -f "$f" \
|| { echo "FAIL: $f missing (model file moved/renamed)"; exit 1; }
if grep -qE '^bool (db_wallet_key_save|db_sapling_key_save|db_wallet_seed_save)[[:space:]]*\(' "$f"; then
    echo "FAIL: $f re-introduced a plaintext wallet-key save — wallet_sqlite is the single writer of the secret columns"
    exit 1
fi
echo "  OK: critical models have before_save hooks"
