/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_wallet_phrase — implementation. See config/boot_wallet_phrase.h. */

#include "config/boot_wallet_phrase.h"

#include "event/event.h"
#include "models/database.h"
#include "support/cleanse.h"
#include "util/blocker.h"
#include "util/boot_status.h"
#include "util/log_macros.h"
#include "wallet/mnemonic.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

bool boot_wallet_phrase_stdout_is_a_terminal(void)
{
    return isatty(STDOUT_FILENO) == 1;
}

bool boot_wallet_phrase_backup_waived(void)
{
    /* Same shape as wallet_at_rest_creation_policy's plaintext opt-in:
     * unset, empty and "0" all mean "not waived", so exporting the variable
     * to 0 in a shell profile does not silently disarm the gate. */
    const char *e = getenv("ZCL_WALLET_NO_PHRASE_BACKUP");
    return e && e[0] && strcmp(e, "0") != 0;
}

enum boot_wallet_phrase_plan
boot_wallet_phrase_plan_for(bool stdout_is_terminal,
                            enum wallet_boot_wallet_action action,
                            enum zcl_operator_lane lane,
                            bool backup_waived)
{
    /* A person is watching: the words can be shown, which is the only way
     * they ever get written on paper. */
    if (stdout_is_terminal)
        return BOOT_WALLET_PHRASE_SHOW;

    /* From here down stdout is a file or a pipe — under the shipped unit
     * that file is node.log. No phrase may be drawn at all, so the only
     * question left is whether creating a backup-less wallet is acceptable
     * or whether the boot must stop. */

    /* The operator said so, in as many words. */
    if (backup_waived)
        return BOOT_WALLET_PHRASE_SKIP;

    /* ZCL_WALLET_PASSPHRASE is set, so the operator has ALREADY made this
     * wallet's at-rest decision deliberately and by hand — that is consent to
     * a wallet whose backup is not twelve written words. Refusing here is what
     * made a brand-new install of the shipped unit crash-loop: it passes
     * -operator-lane=canonical and carries Restart=always, so a fresh datadir
     * exited 1 and restarted forever with no wallet ever created. The security
     * property survives intact because SKIP draws no phrase at all: there are
     * no words to leak into node.log on this path. */
    if (action == WALLET_BOOT_CREATE_ENCRYPTED)
        return BOOT_WALLET_PHRASE_SKIP;

    /* The offline anchor-mint producer: a transient throwaway datadir that
     * folds bodies and exits. It holds no funds and nobody is watching it.
     * REFUSE here is what broke every cure producer. */
    if (action == WALLET_BOOT_CREATE_MINT_EXEMPT)
        return BOOT_WALLET_PHRASE_SKIP;

    /* A declared, non-canonical automated lane. The codebase already has
     * this concept and already downgrades the at-rest gate for it; the
     * phrase gate follows the same declaration rather than inventing a
     * second one. NOTE the lane test comes first: a canonical node that
     * merely passed -allow-plaintext-wallet is still somebody's spendable
     * wallet and still refuses. */
    if (app_operator_lane_is_automated_noncanonical(lane))
        return BOOT_WALLET_PHRASE_SKIP;

    /* Canonical or unknown lane, no passphrase, nothing declared, nothing
     * waived: this is a real spendable wallet, nobody chose anything about how
     * it is kept, and its owner must see its words.
     *
     * NOTE the ordering above: a canonical node that merely passed
     * -allow-plaintext-wallet (CREATE_PLAINTEXT) still refuses. "Store my keys
     * in the clear" is not "I accept having no written backup" — it is the
     * opposite kind of statement, and the file it produces is the only copy. */
    return BOOT_WALLET_PHRASE_REFUSE;
}

/* The refusal. Says what happened, why it is not a bug, and the one thing
 * to do about it — and never contains a word of the phrase, so it is safe
 * on the very stdout it is refusing to trust. */
static void boot_wallet_refuse_non_terminal(void)
{
    static const char *const msg =
        "\n"
        "================ WALLET NOT CREATED ================\n"
        "\n"
        "This node was about to create a new wallet and show you the\n"
        "twelve words that ARE that wallet. Anyone who reads those words\n"
        "can spend every coin in it, forever.\n"
        "\n"
        "This output is NOT going to a terminal. It is going to a file or\n"
        "a pipe — under the shipped service that file is node.log, which\n"
        "is rotated, copied into backups, and readable with\n"
        "'z23 ops logs'. Printing the words there would hand your\n"
        "money to everything that ever reads that file.\n"
        "\n"
        "So nothing was created. There is no half-made wallet and no\n"
        "phrase anywhere on this disk.\n"
        "\n"
        "To create the wallet, run the node ONCE from a terminal:\n"
        "  zclassic23\n"
        "write the twelve words on paper when they appear, stop it, and\n"
        "start the service again as usual. The service will find the\n"
        "wallet and never need to print anything.\n"
        "\n"
        "Or say that a wallet with no written backup is what you want, and\n"
        "it will create one — with the twelve words never drawn at all, so\n"
        "there is nothing to print anywhere. Any ONE of these does it:\n"
        "  ZCL_WALLET_PASSPHRASE=...  encrypt the keys at rest (you have\n"
        "                             then decided how this wallet is kept)\n"
        "  -wallet-no-phrase-backup   'I accept no phrase backup'\n"
        "  -operator-lane=dev         (or soak / test / copy / standby — for\n"
        "                             a node that holds nobody's money)\n"
        "====================================================\n\n";
    fputs(msg, stderr);
    fflush(stderr);
}

/* The SKIP plan's notice. Loud, on stderr, every single boot that creates one
 * of these: a wallet with no written backup is a real thing to know about, and
 * the whole point of the plan is that nobody was watching. Plain English, and
 * it says how to get a wallet that DOES have twelve words — because "no backup
 * phrase" with no way out is not an answer an operator can act on. */
static void boot_wallet_warn_no_phrase_backup(const char *why)
{
    fprintf(stderr,
        "\n"
        "======== NEW WALLET, NO RECOVERY PHRASE ========\n"
        "\n"
        "A new wallet was just created and it does NOT have a twelve-word\n"
        "backup. There are no recovery words for it.\n"
        "\n"
        "Why: this output is not a terminal — it is a file or a pipe, and\n"
        "under the shipped service that file is node.log. Printing the\n"
        "words there would hand your money to everything that ever reads\n"
        "that file, so no words were drawn at all. There are none to\n"
        "leak, and no command can produce them later.\n"
        "\n"
        "Proceeding because %s.\n"
        "\n"
        "What this means: if this datadir ever holds coins, its only\n"
        "backup is the wallet backup FILE:\n"
        "  z23 core wallet backup now\n"
        "Lose the disk and that file and the money is gone.\n"
        "\n"
        "To get a wallet WITH twelve words instead, create it from a\n"
        "terminal before any coins arrive: stop this node, move this\n"
        "datadir aside, run 'zclassic23' once by hand, write the words\n"
        "on paper when they appear, then start the service again. The\n"
        "words are only ever shown at creation — an existing wallet\n"
        "cannot be given a phrase after the fact.\n"
        "===============================================\n\n",
        why ? why : "this wallet is declared disposable");
    fflush(stderr);
}

/* Which declaration let the SKIP plan through — printed in the warning so
 * an operator reading node.log knows which knob to take back. */
static const char *boot_wallet_no_phrase_reason(
    enum wallet_boot_wallet_action action, enum zcl_operator_lane lane,
    bool waived)
{
    if (waived)
        return "-wallet-no-phrase-backup was given";
    if (action == WALLET_BOOT_CREATE_ENCRYPTED)
        return "ZCL_WALLET_PASSPHRASE is set, so you already chose how this "
               "wallet is kept";
    if (action == WALLET_BOOT_CREATE_MINT_EXEMPT)
        return "this is the offline -mint-anchor producer, a throwaway "
               "datadir that holds no funds";
    return app_operator_lane_name(lane);
}

bool boot_wallet_mint_recovery_phrase(struct wallet *w, char *phrase_out,
                                      size_t cap)
{
    GUARD_NOT_NULL(w, "wallet_phrase", "wallet");
    GUARD_NOT_NULL(phrase_out, "wallet_phrase", "phrase_out");
    if (cap < BOOT_WALLET_PHRASE_CAP)
        LOG_FAIL("wallet_phrase", "phrase buffer too small: %zu < %d",
                 cap, (int)BOOT_WALLET_PHRASE_CAP);
    phrase_out[0] = '\0';

    if (!mnemonic_generate(MNEMONIC_12_WORDS, phrase_out, cap))
        LOG_FAIL("wallet_phrase", "could not draw a 12-word recovery phrase");

    if (!wallet_init_from_recovery_phrase(w, phrase_out)) {
        memory_cleanse(phrase_out, cap);
        phrase_out[0] = '\0';
        LOG_FAIL("wallet_phrase",
                 "could not root the wallet on the recovery phrase");
    }
    return true;
}

void boot_wallet_show_recovery_phrase_once(const char *phrase)
{
    if (!phrase || !phrase[0])
        return;

    /* Last line of defence, and the reason this function has exactly one
     * implementation: under the shipped systemd unit stdout IS node.log.
     * A phrase printed there is the wallet's whole spending authority in a
     * plaintext file that gets rotated, copied into backups, and read back
     * by `z23 ops logs`. boot_wallet_create_new refuses long before
     * a phrase exists; this check is here so no future caller can reach
     * the print without it. */
    if (!boot_wallet_phrase_stdout_is_a_terminal()) {
        boot_wallet_refuse_non_terminal();
        return;
    }

    /* stdout, never the log. node.log is copied, shipped and read by other
     * people; these words are the wallet. */
    printf("\n");
    printf("================ WRITE THESE 12 WORDS DOWN ================\n");
    printf("\n");
    printf("  %s\n", phrase);
    printf("\n");
    printf("These twelve words ARE your wallet. Anyone who has them can\n");
    printf("spend your money. Anyone who loses them, and the disk, loses\n");
    printf("the money for good.\n");
    printf("\n");
    printf("Write them on paper, in this order, and keep the paper.\n");
    printf("\n");
    printf("THIS IS THE ONLY TIME THEY WILL EVER BE SHOWN. There is no\n");
    printf("command that prints them again, and that is on purpose: the\n");
    printf("node stores only the key material the words derive, and the\n");
    printf("words cannot be worked back out of it. A command that could\n");
    printf("reprint them would turn one read of the wallet database into\n");
    printf("the loss of every coin in it.\n");
    printf("\n");
    /* The owner's approved wording, verbatim. It also appears in the
     * core.wallet.recovery.restore help text; those are the two surfaces a
     * person can read it on, and it must be on both. Say it plainly and do not
     * soften it: someone who assumes these words work in Electrum will find
     * out otherwise on the worst day. */
    printf("These words restore your money in Z23 only. They will\n");
    printf("not work in Electrum, on a hardware wallet, or in any other\n");
    printf("wallet software. Keep them with a note saying they belong to\n");
    printf("zclassic23. Typing somebody else's words in here would not\n");
    printf("fail either — it would quietly open a different, empty wallet.\n");
    printf("\n");
    printf("To get this wallet back on a new machine:\n");
    printf("  z23 core wallet recovery restore \\\n");
    printf("      --input='{\"phrase\":\"<your 12 words>\",\n");
    printf("                \"datadir\":\"/path/to/empty/datadir\",\n");
    printf("                \"confirm\":true}'\n");
    printf("==========================================================\n");
    printf("\n");
    fflush(stdout);
}

bool boot_wallet_create_new(struct wallet *w, struct wallet_sqlite *ws,
                            struct node_db *ndb,
                            enum wallet_boot_wallet_action action,
                            enum zcl_operator_lane lane)
{
    GUARD_NOT_NULL(w, "wallet_phrase", "wallet");

    /* FIRST, before a single byte is minted or written, decide what happens
     * to the twelve words — because on the REFUSE branch the answer is
     * "nothing happens at all" and that has to be true while there is still
     * nothing to clean up.
     *
     * The words are shown exactly once, and this process's stdout is
     * node.log whenever the node runs as the shipped service. So a
     * spendable wallet created without a terminal would either put its
     * whole spending authority into that file or leave its owner a backup
     * they never saw: refuse, and let the caller (engine/composition/src/boot.c) name a
     * blocker and exit.
     *
     * But the refusal must only fire where nobody has decided anything. Four
     * headless cases HAVE decided, and each takes the SKIP plan instead — a
     * wallet created with NO phrase drawn at all, plus a loud block on stderr
     * saying it has no written backup and how to get one:
     *
     *   - ZCL_WALLET_PASSPHRASE set (action == CREATE_ENCRYPTED): the operator
     *     already chose, by hand, how this wallet is kept at rest.
     *   - the offline -mint-anchor producer.
     *   - a declared dev/soak/test/copy/standby lane.
     *   - -wallet-no-phrase-backup, in as many words.
     *
     * The refusal used to fire for all four, and the first one is the shipped
     * canonical unit's own first boot: platform/deploy/zclassic23.service passes
     * -operator-lane=canonical and carries Restart=always, so a brand-new
     * install exited 1 and restarted forever without ever creating a wallet.
     * -allow-plaintext-wallet is deliberately NOT on that list: choosing to
     * keep keys in the clear is not choosing to have no written backup.
     *
     * The decision table itself is boot_wallet_phrase_plan_for(), which is
     * pure — every case is unit-tested without a boot. */
    const bool waived = boot_wallet_phrase_backup_waived();
    const enum boot_wallet_phrase_plan plan = boot_wallet_phrase_plan_for(
        boot_wallet_phrase_stdout_is_a_terminal(), action, lane, waived);

    if (plan == BOOT_WALLET_PHRASE_REFUSE) {
        boot_wallet_refuse_non_terminal();
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "wallet_creation_refused_stdout_not_a_terminal");
        /* Named HERE, not at the call site, so no future caller can refuse
         * and forget: the caller exits, and a boot that exits with the
         * beacon still reading phase=loading is a silent halt. */
        boot_wallet_creation_blocked();
        return false;
    }
    if (plan == BOOT_WALLET_PHRASE_SKIP)
        boot_wallet_warn_no_phrase_backup(
            boot_wallet_no_phrase_reason(action, lane, waived));

    if (action == WALLET_BOOT_CREATE_PLAINTEXT)
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "wallet_plaintext_created_optin");

    /* Born from twelve words: draw the phrase and root BOTH key trees on
     * the seed it derives BEFORE any key is minted, so every key in the
     * keypool below is recoverable from the words alone.
     *
     * On the SKIP plan no phrase is drawn — not drawn-and-discarded, not
     * drawn-and-not-printed. A phrase that never exists cannot reach
     * node.log, a core file, or a swap page. The wallet mints legacy random
     * keys instead, exactly as every wallet did before phrases existed. */
    char phrase[BOOT_WALLET_PHRASE_CAP];
    phrase[0] = '\0';
    bool phrase_ok = (plan == BOOT_WALLET_PHRASE_SHOW) &&
                     boot_wallet_mint_recovery_phrase(w, phrase,
                                                      sizeof(phrase));
    if (!phrase_ok && plan == BOOT_WALLET_PHRASE_SHOW)
        fprintf(stderr, "WARNING: could not create a recovery phrase for "
            "this wallet; its keys are random and can only be backed up as "
            "a file (core wallet backup now).\n");

    wallet_top_up_key_pool(w, DEFAULT_KEYPOOL_SIZE);
    int64_t pool_generation = wallet_key_pool_generation_ceiling(w);

    if (ws && ws->open) {
        struct zcl_result r = wallet_sqlite_flush_r(ws, w);
        if (!r.ok) {
            fprintf(stderr,
                "\nFATAL: initial keypool flush failed.\n"
                "       code=%d message=%s\n"
                "       source=%s:%d\n"
                "       REFUSING to proceed — fresh keys would be RAM-only.\n\n",
                r.code, r.message, r.source_file ? r.source_file : "?",
                r.source_line);
            event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                        "wallet_keypool_flush_failed code=%d", r.code);
            memory_cleanse(phrase, sizeof(phrase));
            return false;
        }
    } else {
        /* RAM-only wallet: nothing was persisted, so the phrase would name
         * a wallet that will not be here next boot. Never show words the
         * user would write down for nothing. */
        phrase_ok = false;
    }
    wallet_key_pool_mark_persisted_through(w, pool_generation);
    if (ndb && ndb->open)
        node_db_wal_checkpoint(ndb);

    /* The seed is on disk now — the words are true. Show them once. */
    if (phrase_ok)
        boot_wallet_show_recovery_phrase_once(phrase);
    memory_cleanse(phrase, sizeof(phrase));
    printf("New wallet created.\n");
    return true;
}

#define BOOT_WALLET_PHRASE_BLOCKER_ID "wallet_phrase_no_terminal"

void boot_wallet_creation_blocked(void)
{
    /* KEEP THIS UNDER 255 BYTES. boot_status_snapshot.blocker_reason is
     * char[256] and the writer TRUNCATES silently, so a longer reason loses
     * its tail — which is the part that says what to do. The version before
     * this one was 307 bytes and the operator's way out was the half that got
     * cut. The test group asserts the whole thing survived the round trip. */
    static const char *const reason =
        "wallet not created: stdout is not a terminal, so its twelve words "
        "could only go into node.log. Run the node once from a terminal and "
        "write them down, or accept no backup: set ZCL_WALLET_PASSPHRASE, or "
        "pass -wallet-no-phrase-backup or -operator-lane=dev.";

    struct blocker_record rec;
    if (blocker_init(&rec, BOOT_WALLET_PHRASE_BLOCKER_ID, "boot.wallet",
                     BLOCKER_PERMANENT, reason) &&
        blocker_set(&rec) == 0)
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "check=" BOOT_WALLET_PHRASE_BLOCKER_ID);

    /* The registry dies with the process; the beacon does not, and an
     * operator watching a unit that restarts forever has only the file.
     * The writer was armed with this node's datadir at the top of boot
     * (engine/composition/src/boot.c), so this writes into the right place without
     * needing the path handed down through the wallet layer. */
    boot_status_set_blocker(BOOT_WALLET_PHRASE_BLOCKER_ID, reason);
}

void boot_wallet_adopt_seed_if_it_governs(struct wallet *w)
{
    if (w && w->sapling_keys.has_seed)
        (void)wallet_hd_adopt_seed(w, w->sapling_keys.seed);
}
