/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wallet_create_service — implementation.
 * See services/wallet_create_service.h. */

#include "services/wallet_create_service.h"

#include "support/cleanse.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* A <datadir>/wallet directory is a pre-SQLite wallet that boot would import
 * on its next start. It holds keys this command cannot see, so the datadir is
 * not empty. */
static bool wcs_legacy_wallet_present(const char *datadir)
{
    char legacy[2048];
    struct stat st;
    int n = snprintf(legacy, sizeof(legacy), "%s/wallet", datadir);
    return n <= 0 || (size_t)n >= sizeof(legacy) || lstat(legacy, &st) == 0;
}

struct zcl_result wallet_create_phrase(char *out, size_t cap)
{
    if (!out || cap < MNEMONIC_MAX_PHRASE_SIZE)
        return ZCL_ERR(-69, "phrase buffer is too small");
    out[0] = '\0';
    if (!mnemonic_generate(MNEMONIC_24_WORDS, out, cap)) {
        memory_cleanse(out, cap);
        return ZCL_ERR(-69, "could not draw a recovery phrase");
    }
    return ZCL_OK;
}

void wallet_create_report_cleanse(struct wallet_create_report *rep)
{
    if (rep)
        memory_cleanse(rep->phrase, sizeof(rep->phrase));
}

struct zcl_result wallet_create_run(const struct wallet_create_request *req,
                                    struct wallet_create_report *out)
{
    if (!out)
        return ZCL_ERR(-69, "report is NULL");
    memset(out, 0, sizeof(*out));
    struct zcl_result live = wallet_recovery_refuse_live_process();
    if (!live.ok)
        return live;
    if (!req || !req->datadir || !req->datadir[0])
        return ZCL_ERR(-63, "datadir path is empty");
    if (!req->passphrase || strlen(req->passphrase) <
                                (size_t)WALLET_CREATE_MIN_PASSPHRASE)
        return ZCL_ERR(-68,
            "the passphrase is missing or shorter than %d bytes. The wallet "
            "is encrypted from its first write, so it cannot be created "
            "without one. Nothing was written",
            WALLET_CREATE_MIN_PASSPHRASE);

    if (wcs_legacy_wallet_present(req->datadir))
        return ZCL_ERR(-62,
            "%s holds a wallet directory from an earlier version, so it is not "
            "an empty datadir. Nothing was written. Create into a new datadir",
            req->datadir);

    char phrase[MNEMONIC_MAX_PHRASE_SIZE];
    if (!wallet_create_phrase(phrase, sizeof(phrase)).ok)
        return ZCL_ERR(-69, "could not draw a recovery phrase. Nothing was "
                            "written");

    struct wallet_recovery_request rr = {
        .phrase = phrase,
        .datadir = req->datadir,
        .passphrase = req->passphrase,
        .shielded_only = true,
        .record_birthday = true,
    };
    struct zcl_result r = wallet_recovery_run(&rr, &out->recovery);
    if (r.ok)
        memcpy(out->phrase, phrase, strlen(phrase) + 1);
    memory_cleanse(phrase, sizeof(phrase));
    return r;
}
