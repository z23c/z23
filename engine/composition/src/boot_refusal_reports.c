/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Operator-facing text for the boot refusals raised from engine/composition/src/boot.c.
 * Contract + why these live apart from the decision sites:
 * engine/composition/include/config/boot_refusal_reports.h. */

#include "config/boot_refusal_reports.h"

#include "config/boot_error.h"
#include "platform/current_identity.h"
#include "util/result.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define WALLET_PHASE "wallet_load"
#define WALLET_RECOVERY_DOC "docs/WALLET_PERSISTENCE_RECOVERY.md"

/* Write the parent directory of `path` into `out`. "/a/b" -> "/a";
 * "/a" -> "/"; "a" -> ".". */
static void parent_dir_of(const char *path, char *out, size_t cap)
{
    (void)snprintf(out, cap, "%s", path ? path : "");
    char *slash = strrchr(out, '/');
    if (slash && slash != out)
        *slash = '\0';
    else if (slash)
        (void)snprintf(out, cap, "/");
    else
        (void)snprintf(out, cap, ".");
}

/* The first move for every wallet refusal: preserve the datadir. `cp -a` is
 * read-only with respect to the original, so this is always safe to suggest
 * and always available. */
static void rescue_copy_command(const char *datadir, char *out, size_t cap)
{
    (void)snprintf(out, cap, "cp -a %s %s.rescue-copy", datadir, datadir);
}

void boot_report_datadir_create_failed(const char *datadir, int mkdir_errno)
{
    const char *dd = datadir && datadir[0] ? datadir : "(unset)";
    char parent[1024];
    parent_dir_of(dd, parent, sizeof(parent));

    char mk[1100], ls[1100];
    (void)snprintf(mk, sizeof(mk), "mkdir -p %s", dd);
    (void)snprintf(ls, sizeof(ls), "ls -ld %s", parent);

    /* Only offer `mkdir -p` when a missing parent is what actually failed.
     * On EACCES/EROFS the same mkdir would fail identically, so suggesting it
     * would spend the reader's next move proving what this line already
     * measured. */
    const struct boot_error_next missing_parent[] = {
        { mk, "create the directory INCLUDING its parents; the node's own "
              "create is single-level and fails when a parent is missing" },
        { ls, "confirm the parent exists and is writable by the user running "
              "the node" },
    };
    const struct boot_error_next not_permitted[] = {
        { ls, "compare the parent's owner and mode against the user running "
              "the node; the create was refused, not merely missing a "
              "parent" },
        { "id -un", "print the user this process runs as" },
    };
    bool parent_missing = mkdir_errno == ENOENT;
    char identity[192];
    if (!platform_current_identity(identity, sizeof(identity)))
        (void)snprintf(identity, sizeof(identity), "unavailable");
    boot_error_report(BOOT_ERROR_FATAL, "BOOT_DATADIR_CREATE_FAILED",
                      "datadir_select",
                      "the data directory does not exist and could not be "
                      "created",
                      parent_missing ? missing_parent : not_permitted, 2,
                      "datadir=%s parent=%s identity=%s mkdir_errno=%s",
                      dd, parent, identity, strerror(mkdir_errno));
}

void boot_report_wallet_persistence_open_failed(
    const char *datadir, const struct zcl_result *open_result,
    long long wallet_key_rows)
{
    const char *dd = datadir && datadir[0] ? datadir : "(unset)";
    char cp[1200], ls[1500];
    rescue_copy_command(dd, cp, sizeof(cp));
    (void)snprintf(ls, sizeof(ls),
                   "ls -l %s/node.db %s/node.db-wal %s/node.db-shm",
                   dd, dd, dd);
    const struct boot_error_next next[] = {
        { cp, "copy the whole data directory BEFORE any repair — the private "
              "keys are still intact inside node.db and this refusal exists "
              "to keep them that way" },
        { ls, "a persistence-open failure is almost always ownership, mode, "
              "or truncation on these three files; their presence and sizes "
              "say which" },
    };
    boot_error_report(BOOT_ERROR_FATAL,
                      "BOOT_WALLET_PERSISTENCE_OPEN_FAILED", WALLET_PHASE,
                      "wallet persistence initialisation failed while "
                      "existing wallet keys are on disk — refusing to boot "
                      "rather than generate a fresh keypool over them",
                      next, 2,
                      "wsql_code=%d wsql_message=%s source=%s:%d "
                      "wallet_keys_rows=%lld recovery_doc=%s",
                      open_result ? open_result->code : 0,
                      open_result && open_result->message[0]
                          ? open_result->message
                          : "wallet_sqlite_open_r returned !ok",
                      open_result && open_result->source_file
                          ? open_result->source_file
                          : "engine/composition/src/boot.c",
                      open_result ? open_result->source_line : 0,
                      wallet_key_rows, WALLET_RECOVERY_DOC);
}

void boot_report_wallet_canary_failed(const char *datadir, int canary_code,
                                      const char *canary_message,
                                      long long wallet_key_rows)
{
    const char *dd = datadir && datadir[0] ? datadir : "(unset)";
    char cp[1200], df[1200];
    rescue_copy_command(dd, cp, sizeof(cp));
    (void)snprintf(df, sizeof(df), "df -h %s", dd);
    const struct boot_error_next next[] = {
        { cp, "copy the whole data directory BEFORE any repair — the existing "
              "keys are intact and this refusal exists to keep them that way" },
        { df, "the canary writes then reads a probe row through the wallet's "
              "own handle, so a full or read-only filesystem is the most "
              "common cause" },
    };
    boot_error_report(BOOT_ERROR_FATAL, "BOOT_WALLET_CANARY_FAILED",
                      WALLET_PHASE,
                      "the wallet write/read self-test failed while existing "
                      "wallet keys are on disk — refusing to proceed rather "
                      "than risk overwriting them",
                      next, 2,
                      "canary_code=%d canary_message=%s "
                      "source=contexts/wallet/modules/wallet/src/wallet_canary.c "
                      "wallet_keys_rows=%lld recovery_doc=%s",
                      canary_code,
                      canary_message && canary_message[0] ? canary_message
                                                          : "(no message)",
                      wallet_key_rows, WALLET_RECOVERY_DOC);
}

void boot_report_wallet_keystore_count_mismatch(const char *datadir,
                                                long long wallet_key_rows,
                                                size_t loaded_keys)
{
    const char *dd = datadir && datadir[0] ? datadir : "(unset)";
    char cp[1200];
    rescue_copy_command(dd, cp, sizeof(cp));
    const struct boot_error_next next[] = {
        { cp, "copy the whole data directory BEFORE anything else — it is the "
              "only evidence of the divergence and it still holds every key "
              "row" },
    };
    boot_error_report(BOOT_ERROR_FATAL,
                      "BOOT_WALLET_KEYSTORE_COUNT_MISMATCH", WALLET_PHASE,
                      "the number of keys loaded into memory does not equal "
                      "the number of rows on disk — refusing to proceed, "
                      "because the next wallet flush would write the smaller "
                      "set back and destroy the difference",
                      next, 1,
                      "wallet_keys_rows=%lld loaded_keystore=%zu "
                      "source=engine/composition/src/boot.c recovery_doc=%s",
                      wallet_key_rows, loaded_keys, WALLET_RECOVERY_DOC);
}

void boot_report_wallet_scrub_failed(const char *datadir,
                                     const struct zcl_result *scrub_result)
{
    const char *dd = datadir && datadir[0] ? datadir : "(unset)";
    char cp[1200];
    rescue_copy_command(dd, cp, sizeof(cp));
    const struct boot_error_next next[] = {
        { cp, "copy the whole data directory BEFORE anything else — the "
              "scrub failed mid-upgrade and the on-disk rows are the only "
              "copy of those keys" },
    };
    boot_error_report(BOOT_ERROR_FATAL,
                      "BOOT_WALLET_PLAINTEXT_SCRUB_FAILED", WALLET_PHASE,
                      "wrapping legacy plaintext secret rows into WKS1 "
                      "envelopes failed — refusing to proceed, because "
                      "continuing would leave plaintext key material at "
                      "rest on an encrypted wallet",
                      next, 1,
                      "scrub_code=%d scrub_message=%s source=%s:%d "
                      "recovery_doc=%s",
                      scrub_result ? scrub_result->code : 0,
                      scrub_result && scrub_result->message[0]
                          ? scrub_result->message : "(no message)",
                      scrub_result && scrub_result->source_file
                          ? scrub_result->source_file : "?",
                      scrub_result ? scrub_result->source_line : 0,
                      WALLET_RECOVERY_DOC);
}
