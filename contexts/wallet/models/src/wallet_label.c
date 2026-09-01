/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet address label / address-book model. Backs the setlabel /
 * getaddressesbylabel / listlabels RPC handlers and the
 * core.wallet.address.label(.by-label) native commands
 * (contexts/wallet/controllers/src/wallet_label_controller.c). One row per labeled
 * address, keyed by address so a re-label overwrites in place. */

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "models/wallet_label.h"
#include "models/model_text.h"
#include <string.h>

DEFINE_MODEL_CALLBACKS(wallet_label)

static bool wallet_label_before_validate(void *record, void *ctx)
{
    struct db_wallet_label *l = record;

    (void)ctx;
    if (!l)
        return false;
    model_trim_ascii(l->address);
    model_trim_ascii(l->label);
    return true;
}

/* Registers wallet_label's before_validate hook once on the callback
 * singleton (db_wallet_label_callbacks returns a static struct). */
static struct ar_callbacks *wallet_label_callbacks_ready(void)
{
    struct ar_callbacks *cbs = db_wallet_label_callbacks();
    static bool hooks_done = false;
    if (!hooks_done) {
        ar_register_before_validate(cbs, wallet_label_before_validate);
        hooks_done = true;
    }
    return cbs;
}

bool db_wallet_label_validate(const struct db_wallet_label *l,
                              struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_string_present(errors, l->address, "address");
    validates_custom(errors, strlen(l->address) <= WALLET_LABEL_ADDRESS_MAX,
                     "address", "exceeds max length 255");
    validates_custom(errors, model_string_is_printable(l->address),
                     "address", "contains non-printable characters");
    /* label may be "" (the default/unlabeled bucket) but never overlong or
     * non-printable when set. */
    validates_custom(errors, strlen(l->label) <= WALLET_LABEL_MAX,
                     "label", "exceeds max length 255");
    validates_custom(errors,
                     l->label[0] == '\0' || model_string_is_printable(l->label),
                     "label", "contains non-printable characters");
    return !ar_errors_any(errors);
}

bool db_wallet_label_save(struct node_db *ndb, const struct db_wallet_label *l)
{
    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs;

    if (!ndb || !ndb->open || !l)
        LOG_FAIL("model", "db_wallet_label_save: bad args");

    cbs = wallet_label_callbacks_ready();
    int64_t now = (int64_t)platform_time_wall_time_t();
    AR_ADHOC_SAVE(ndb, s,
        "INSERT OR REPLACE INTO wallet_labels (address,label,updated_at) "
        "VALUES (?,?,?)",
        cbs, "wallet_label", l, db_wallet_label_validate,
        AR_BIND_TEXT(s, 1, l->address);
        AR_BIND_TEXT(s, 2, l->label);
        AR_BIND_INT(s, 3, now));
}

bool db_wallet_label_find(struct node_db *ndb, const char *address,
                          struct db_wallet_label *out)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !address || !address[0] || !out)
        LOG_FAIL("model", "db_wallet_label_find: bad args");
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT address,label,updated_at FROM wallet_labels WHERE address=?",
        AR_BIND_TEXT(s, 1, address),
        AR_READ_STR(s, 0, out->address, sizeof(out->address));
        AR_READ_STR(s, 1, out->label, sizeof(out->label));
        out->updated_at = AR_COL_INT(s, 2));
}

int db_wallet_label_list_by_label(struct node_db *ndb, const char *label,
                                  struct db_wallet_label *out, size_t max)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !label || !out || max == 0) {
        LOG_ERROR("model", "db_wallet_label_list_by_label: bad args");
        return 0;
    }
    AR_QUERY_LIST(ndb, s,
        "SELECT address,label,updated_at FROM wallet_labels "
        "WHERE label=? ORDER BY address",
        out, max,
        AR_BIND_TEXT(s, 1, label),
        AR_READ_STR(s, 0, out[count].address, sizeof(out[count].address));
        AR_READ_STR(s, 1, out[count].label, sizeof(out[count].label));
        out[count].updated_at = AR_COL_INT(s, 2));
}

int db_wallet_label_list_distinct(struct node_db *ndb,
                                  struct db_wallet_label *out, size_t max)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !out || max == 0) {
        LOG_ERROR("model", "db_wallet_label_list_distinct: bad args");
        return 0;
    }
    AR_QUERY_LIST(ndb, s,
        "SELECT DISTINCT label FROM wallet_labels ORDER BY label",
        out, max,
        (void)0,
        AR_READ_STR(s, 0, out[count].label, sizeof(out[count].label)));
}
