#!/usr/bin/env bash
# Program H enforcement gate — the node.db `utxos` mirror is a demoted read
# surface (OBSERVE-style ratchet).
#
# The canonical UTXO set is the kernel coins store; the node.db `utxos` table is
# an operator-view mirror that Program H4 deletes once no consensus reader
# depends on it. This gate freezes the CURRENT set of app/config files that read
# `FROM utxos`: a NEW such reader fails the build; as Program H4 re-points a
# reader at the kernel its baseline row goes stale and must be removed
# (shrink-only). Scope is the demotion-relevant trees only (app/services,
# app/jobs, app/conditions, engine/composition/src) — explorer/wallet views keep their own
# mirror coupling until H4.
#
# Model: tools/scripts/check_frontier_single_writer.sh (same ratchet discipline).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-utxos-mirror-read "$@"
