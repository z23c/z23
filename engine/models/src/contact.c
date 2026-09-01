/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "models/contact.h"
#include "models/model_text.h"
#include "storage/small_projections.h"
#include <string.h>
#include <time.h>

DEFINE_MODEL_CALLBACKS(contact)

static bool contact_before_validate(void *record, void *ctx)
{
    struct db_contact *contact = record;

    (void)ctx;
    if (!contact)
        return false;
    model_trim_ascii(contact->address);
    model_trim_ascii(contact->name);
    return true;
}

/* Projection emit runs as a registered after_save callback (the
 * wallet_key pattern) so it fires through the AR lifecycle on a successful
 * save instead of as inline post-save code. Best-effort: a failed emit is
 * logged but does not fail the save. */
static void contact_after_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_contact *c = record;
    if (c->last_used < 0 || c->last_used > UINT32_MAX ||
        !contacts_projection_emit_set(c->address, c->name) ||
        !contacts_projection_emit_touched(c->address,
                                          (uint32_t)c->last_used)) {
        LOG_WARN("model", "contacts projection emit failed for save");
    }
}

/* Registers contact's before_validate + after_save hooks once on the callback
 * singleton (db_contact_callbacks returns a static struct). */
static struct ar_callbacks *contact_callbacks_ready(void)
{
    struct ar_callbacks *cbs = db_contact_callbacks();
    static bool hooks_done = false;
    if (!hooks_done) {
        ar_register_before_validate(cbs, contact_before_validate);
        ar_register_after_save(cbs, contact_after_save);
        hooks_done = true;
    }
    return cbs;
}

bool db_contact_validate(const struct db_contact *c, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_string_present(errors, c->address, "address");
    validates_string_present(errors, c->name, "name");
    validates_non_negative(errors, c, last_used);
    validates_custom(errors,
        strlen(c->address) <= CONTACT_ADDRESS_MAX,
        "address", "exceeds max length 255");
    validates_custom(errors,
        strlen(c->name) <= CONTACT_NAME_MAX,
        "name", "exceeds max length 63");
    validates_custom(errors,
        model_string_is_printable(c->address),
        "address", "contains non-printable characters");
    validates_custom(errors,
        model_string_is_printable(c->name),
        "name", "contains non-printable characters");
    return !ar_errors_any(errors);
}

bool db_contact_save(struct node_db *ndb, const struct db_contact *c)
{
    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs;

    if (!ndb || !ndb->open || !c)
        return false;
    if (c->last_used == 0)
        ((struct db_contact *)c)->last_used = (int64_t)platform_time_wall_time_t();

    cbs = contact_callbacks_ready();
    AR_BEGIN_SAVE(cbs, "contact", c, db_contact_validate);

    if (sqlite3_prepare_v2(ndb->db,
            "INSERT OR REPLACE INTO contacts (address,name,last_used) "
            "VALUES (?,?,?)",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;

    AR_BIND_TEXT(s, 1, c->address);
    AR_BIND_TEXT(s, 2, c->name);
    AR_BIND_INT(s, 3, c->last_used);
    if (!AR_STEP_DONE(s)) {
        LOG_WARN("model", "contact save failed: %s", sqlite3_errmsg(ndb->db));
        AR_FINALIZE(s);
        return false;
    }
    AR_FINALIZE(s);
    AR_FINISH_SAVE(cbs, c, true);
}

int db_contact_recent(struct node_db *ndb, struct db_contact *out, size_t max)
{
    sqlite3_stmt *s = NULL;
    int count = 0;

    if (!ndb || !ndb->open || !out || max == 0)
        return 0;

    AR_PREPARE_RET(ndb, s,
        "SELECT address,name,last_used FROM contacts "
        "ORDER BY last_used DESC LIMIT ?",
        0);
    AR_BIND_INT(s, 1, (int)max);
    AR_LIST_ROWS(s, out, max,
        AR_READ_STR(s, 0, out[count].address, sizeof(out[count].address));
        AR_READ_STR(s, 1, out[count].name, sizeof(out[count].name));
        out[count].last_used = AR_COL_INT(s, 2));
    AR_FINALIZE(s);
    return count;
}
