/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_wallet_phrase — the recovery phrase a brand-new wallet is born with.
 *
 * Before this existed, the only backup this node could offer was a file:
 * lose the disk and the backup together and the money was gone. A wallet
 * created now is born from twelve words instead. The words are shown once,
 * at creation, and never again — the node keeps only the 32-byte seed they
 * derive, and a seed cannot be turned back into words. That is the whole
 * point: if the phrase could be reprinted, every read of node.db would be a
 * total compromise of the wallet.
 *
 * Split out of boot.c so the boot function stays readable and so the
 * once-only print has exactly one implementation.
 */

#ifndef ZCL_CONFIG_BOOT_WALLET_PHRASE_H
#define ZCL_CONFIG_BOOT_WALLET_PHRASE_H

/* enum wallet_boot_wallet_action + enum zcl_operator_lane: the two facts
 * that decide whether the wallet about to be created is a person's spendable
 * wallet or a declared throwaway. */
#include "config/boot.h"

#include <stdbool.h>
#include <stddef.h>

struct wallet;
struct wallet_sqlite;
struct node_db;

/* Buffer a caller must provide for a phrase. */
#include "wallet/mnemonic.h"
#define BOOT_WALLET_PHRASE_CAP MNEMONIC_MAX_PHRASE_SIZE

/* Draw a fresh 12-word BIP39 phrase and make `w` descend from it: the
 * Sapling (ZIP32) and transparent (BIP32) trees are both re-rooted on the
 * seed the phrase derives, so every key minted afterwards is recoverable
 * from the words alone. Call on a wallet with NO keys yet.
 *
 * On success the phrase is written to `phrase_out` — the caller owns it,
 * must show it once, and must memory_cleanse() it. On failure `phrase_out`
 * is set to the empty string and the wallet is left untouched (it will mint
 * legacy random keys, which is exactly the old behaviour).
 *
 * The phrase is never logged and never written to disk by this call. */
bool boot_wallet_mint_recovery_phrase(struct wallet *w, char *phrase_out,
                                      size_t cap);

/* True when this process's stdout is a terminal a person is looking at,
 * rather than a file or a pipe. The whole phrase story turns on it: under
 * the shipped systemd unit stdout is redirected to node.log, and node.log
 * is rotated, copied into backups and read back by `z23 ops logs`,
 * so a phrase printed there is the wallet's entire spending authority
 * sitting in plaintext in a file nobody treats as a secret. */
bool boot_wallet_phrase_stdout_is_a_terminal(void);

/* Print the once-only phrase block to stdout: the words, what they are for,
 * and the fact that no command can ever show them again. Call ONLY after
 * the wallet's seed has been durably flushed — showing a phrase for a
 * wallet that did not persist would be a lie the user acts on.
 *
 * Prints NOTHING when stdout is not a terminal; it explains the refusal on
 * stderr instead. That is a hard floor, not a preference. */
void boot_wallet_show_recovery_phrase_once(const char *phrase);

/* True when the operator has explicitly said "create this wallet even
 * though nobody can be shown its twelve words" — the `-wallet-no-phrase-
 * backup` flag, which the argv loop maps onto ZCL_WALLET_NO_PHRASE_BACKUP
 * the same way `-allow-plaintext-wallet` maps onto its env var. Unset,
 * empty and "0" all mean "not waived". Pure env read; reentrant. */
bool boot_wallet_phrase_backup_waived(void);

/* What to do about the twelve words for a wallet that is about to be
 * created. Three outcomes, because there are three genuinely different
 * situations and collapsing any two of them costs someone something:
 *
 *   SHOW   — a person is watching stdout. Draw the phrase, root the wallet
 *            on it, print it once.
 *   SKIP   — no terminal, but the operator HAS decided something about this
 *            wallet: ZCL_WALLET_PASSPHRASE is set (an at-rest decision made
 *            by hand, which is consent to a wallet backed by something other
 *            than written words), or it is the offline -mint-anchor producer,
 *            or a declared dev/soak/test/copy/standby lane, or the backup was
 *            explicitly waived. Create it, draw NO phrase at all, and say
 *            loudly that it has no written backup and how to get one. The
 *            words are never generated, so they cannot leak.
 *   REFUSE — no terminal, nothing decided, and this IS somebody's spendable
 *            wallet. Creating it would either print the words into node.log
 *            or leave the owner a wallet whose only backup they were never
 *            shown. Nothing is drawn, minted or flushed.
 *
 * -allow-plaintext-wallet is deliberately NOT a SKIP: "keep my keys in the
 * clear" is not "I accept having no written backup".
 *
 * Pure and total: no globals, no env reads (both opt-ins are passed in), so
 * the whole matrix is unit-testable without a boot. */
enum boot_wallet_phrase_plan {
    BOOT_WALLET_PHRASE_SHOW = 0,
    BOOT_WALLET_PHRASE_SKIP,
    BOOT_WALLET_PHRASE_REFUSE,
};

enum boot_wallet_phrase_plan
boot_wallet_phrase_plan_for(bool stdout_is_terminal,
                            enum wallet_boot_wallet_action action,
                            enum zcl_operator_lane lane,
                            bool backup_waived);

/* Create the first-run wallet: a fresh recovery phrase, both key trees
 * rooted on the seed it derives, the standard keypool minted from that
 * seed, one durable flush, and then — only once the seed is provably on
 * disk — the words printed once for the user to write down.
 *
 * `action` is the boot-site at-rest decision (wallet_at_rest_boot_decision)
 * and `lane` the declared operator lane; together with whether stdout is a
 * terminal and whether the operator waived the backup they select the
 * phrase plan above. CREATE_PLAINTEXT is still recorded as a boot event
 * exactly as before.
 *
 * Returns false when the keypool could not be made durable, having already
 * printed the FATAL diagnostic and emitted the boot event; the caller must
 * refuse to continue, because the alternative is a node running on keys
 * that exist only in RAM. Never shows a phrase on that path.
 *
 * Also returns false, BEFORE creating anything at all, on the REFUSE plan:
 * the words could only be written to a log file and this is a spendable
 * wallet. Nothing is drawn, minted or flushed on that path, so there is no
 * half-made wallet to clean up. That path names its own blocker (id
 * "wallet_phrase_no_terminal", see boot_wallet_creation_blocked) before it
 * returns, so a caller that exits cannot leave boot_status.json reading
 * phase=loading with no reason in it. The operator's move is to run the
 * node once from a terminal, or to set ZCL_WALLET_PASSPHRASE, or to waive
 * the backup on purpose, or to declare the lane. */
bool boot_wallet_create_new(struct wallet *w, struct wallet_sqlite *ws,
                            struct node_db *ndb,
                            enum wallet_boot_wallet_action action,
                            enum zcl_operator_lane lane);

/* Name the refusal above. Raises the typed blocker
 * `wallet_phrase_no_terminal` in the in-process registry AND writes it into
 * the already-armed <datadir>/boot_status.json, which is the only one of
 * the two that survives the exit(1) the caller then makes. Called by
 * boot_wallet_create_new itself on the REFUSE path; exposed so a test can
 * assert the beacon directly. Never leave the beacon at
 * phase=loading/stage=db_open with no reason: that is indistinguishable
 * from a hang. */
void boot_wallet_creation_blocked(void);

/* On an EXISTING wallet, re-point the transparent HD chain at the seed
 * just loaded from disk — but only when that seed provably grew the keys
 * already in the keystore (wallet_hd_adopt_seed makes that call by
 * derivation). A wallet created before recovery phrases is left exactly as
 * it was found: legacy random key generation, unchanged derivation. */
void boot_wallet_adopt_seed_if_it_governs(struct wallet *w);

#endif /* ZCL_CONFIG_BOOT_WALLET_PHRASE_H */
