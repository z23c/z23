<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Wallet creation before chain synchronization

A new Android wallet can be saved before its node has connected the chain.
For words already displayed by the app, `birthday_at_local_tip` uses the
release's immutable mainnet anchor as the scan floor. The caller must have
generated those words after that release was built. A delayed write or retry
cannot move the floor past a payment received after the words were displayed.
Without an anchor, coverage begins at genesis. Ordinary restores retain their
existing full-history or explicit verified-birthday behavior.

The unread marker is persisted before the birthday write. Boot validates the
stored floor against the active chain. An unreached floor remains unread;
a matching floor still requires a scan from that floor. A changed floor or a
reorganization below it requires coverage from genesis. Timestamp shortcuts
cannot skip a pending range, and incomplete or locked-key scans cannot erase
that range.

## Focused evidence

On 2026-11-03, `make t-fast-exact
ONLY=wallet_create,tip_finalize_post_step,wallet_rescan_coverage` passed all
three selected groups, without cached groups or skips (68.8 seconds).
The fixtures cover an unsynced save, an exposed phrase saved after local
blocks advance from the anchor at 1000 to 5000, floor verification during tip
finalization, restart, reorganization, and incomplete scan retention.
The delayed-save fixture keeps payment height 1001 inside the scan range.
These are isolated synthetic fixtures, not measurements of mainnet wallet
funds or phone performance. Public help wording changed after this focused run
and is covered by the subsequent candidate gates.

Independent source review accepted the birthday repair and its public timing
contract. Required candidate gates and native landing receipts remain the
publication authority.

## Remaining acceptance

Automatic completion of the pending scan during live synchronization needs a
separate lifecycle-safe worker path and end-to-end evidence. This change does
not claim that behavior, a completed phone sync, or final device acceptance.

## Integration with the balance cache

A newly created wallet has no observed balance until its node answers. Setup
therefore does not write a synthetic zero into the last-known balance cache.
The app regression starts with an unanswered node and requires no amount or
cache file, then supplies a real summary and requires its reported balance.
Existing encrypted caches still retain only previously observed summaries.

## Command description budget

On 2026-11-04, the restore description exceeded its 2816-byte rendering cap
by 72 bytes. Shortening the introductory text preserved the phrase-compatibility,
empty-directory, birthday-anchor and unread-range warnings. The focused
`check-describe-budget` gate and its overflow selftest passed: all 844 leaves
rendered, the largest used 2814 bytes, and no pre-existing baseline was needed.

## Catch-up source size

Integration measured the catch-up service at 1502 lines after the fork-rewind
change, above the 1500-line file-size cap. Its introductory historical narrative
was shortened without changing executable code or the recovery result contract.
The focused file-size gate passed across 2684 files; the candidate file contains
1476 lines before the five-line upstream fork-rewind addition.
