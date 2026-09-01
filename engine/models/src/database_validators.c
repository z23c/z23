/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ar-validate-skip:registry-module-not-a-row
 *   This file IS the model-validator registry; it has no record type
 *   of its own. Lint marker keeps check-model-validation honest.
 *
 * Database Validator Registry — Implementation
 * -------------------------------------------
 * Thin wrappers around every model's existing `_validate()` function,
 * registered under the SQLite table name.  Validation is already wired into
 * each `db_<model>_save()` via `AR_BEGIN_SAVE` / `AR_VALIDATE_RECORD`; this
 * registry is the *programmatic* surface used by tests, metrics, and
 * anything that needs to introspect the validator inventory without
 * pulling in the full record-save paths.
 *
 * On failure we:
 *   - join errors with "; " into err_out (if non-NULL)
 *   - emit EV_MODEL_VALIDATION_FAILED with payload "model=<table> errors=..."
 *
 * See `database_validators.h` for the public API contract.
 */

#include "models/database_validators.h"
#include "models/activerecord.h"
#include "models/block.h"
#include "models/contact.h"
#include "models/file_offer.h"
#include "models/file_service.h"
#include "models/mempool_entry.h"
#include "models/onion_announcement.h"
#include "models/peer.h"
#include "models/store.h"
#include "models/swap_contract.h"
#include "models/tx_index.h"
#include "models/utxo.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"
#include "models/yardsale_plan.h"
#include "models/zcode_science.h"
#include "models/zmsg.h"
#include "models/znam.h"
#include "models/zslp.h"
#include "models/zswap_ad.h"
#include "models/shop_want.h"
#include "models/shop_fulfill.h"
#include "event/event.h"

#include <string.h>

/* ── Registry state ──────────────────────────────────────────── */

struct db_validator_entry {
    char            table[48];
    db_validator_fn fn;
};

static struct db_validator_entry g_validators[DB_VALIDATOR_MAX];
static int g_validator_count = 0;

/* ── Registry primitives ─────────────────────────────────────── */

static int find_slot(const char *table)
{
    if (!table) return -1;
    for (int i = 0; i < g_validator_count; i++) {
        if (strncmp(g_validators[i].table, table, sizeof(g_validators[i].table)) == 0)
            return i;
    }
    return -1;
}

void db_register_validator(const char *table, db_validator_fn fn)
{
    if (!table || !table[0]) return;
    int idx = find_slot(table);
    if (fn == NULL) {
        /* Unregister */
        if (idx < 0) return;
        for (int i = idx; i < g_validator_count - 1; i++)
            g_validators[i] = g_validators[i + 1];
        g_validator_count--;
        return;
    }
    if (idx >= 0) {
        g_validators[idx].fn = fn;
        return;
    }
    if (g_validator_count >= DB_VALIDATOR_MAX) return;
    snprintf(g_validators[g_validator_count].table,
             sizeof(g_validators[g_validator_count].table),
             "%s", table);
    g_validators[g_validator_count].fn = fn;
    g_validator_count++;
}

bool db_run_validators_for(const char *table, const void *row,
                           char *err_out, size_t err_cap)
{
    if (err_out && err_cap > 0) err_out[0] = '\0';
    if (!table || !table[0]) return true;
    int idx = find_slot(table);
    if (idx < 0) return true;  /* no validator = pass */
    if (!row) {
        if (err_out && err_cap > 0)
            snprintf(err_out, err_cap, "row is null");
        event_emitf(EV_MODEL_VALIDATION_FAILED, 0,
                    "model=%s errors=row is null", table);
        return false;
    }
    char local_err[AR_ERROR_MAX];
    local_err[0] = '\0';
    bool ok = g_validators[idx].fn(row, local_err, sizeof(local_err));
    if (!ok) {
        if (err_out && err_cap > 0)
            snprintf(err_out, err_cap, "%s", local_err);
        event_emitf(EV_MODEL_VALIDATION_FAILED, 0,
                    "model=%s errors=%s", table,
                    local_err[0] ? local_err : "(unspecified)");
    }
    return ok;
}

int db_validator_count(void)
{
    return g_validator_count;
}

const char *db_validator_table_at(int index)
{
    if (index < 0 || index >= g_validator_count) return NULL;
    return g_validators[index].table;
}

bool db_validator_has(const char *table)
{
    return find_slot(table) >= 0;
}

void db_validator_reset(void)
{
    g_validator_count = 0;
}

/* ── Shared error formatter ──────────────────────────────────── */

static bool finish(struct ar_errors *errs, char *err_out, size_t err_cap)
{
    if (!ar_errors_any(errs)) return true;
    if (err_out && err_cap > 0)
        ar_errors_full_messages(errs, err_out, err_cap);
    return false;
}

/* ── Wrappers: one per SQL table ─────────────────────────────── *
 *
 * Each wrapper casts `row` to the model's struct, runs its existing
 * _validate() function, then joins any errors into err_out. The vast
 * majority differ only in (name, validate-fn, cast-type), so generate
 * them from one template instead of hand-copying the 4-line body.
 */

#define DEFINE_VAL_WRAPPER(fn_name, validate_fn, cast_type)            \
    static bool fn_name(const void *row, char *err, size_t cap)        \
    {                                                                  \
        struct ar_errors e; ar_errors_clear(&e);                      \
        validate_fn((const cast_type *)row, &e);                      \
        return finish(&e, err, cap);                                  \
    }

DEFINE_VAL_WRAPPER(val_block,              db_block_validate,              struct db_block)
DEFINE_VAL_WRAPPER(val_contact,            db_contact_validate,            struct db_contact)
DEFINE_VAL_WRAPPER(val_file_service,       db_file_service_validate,       struct db_file_service)
DEFINE_VAL_WRAPPER(val_file_offer,         db_file_offer_validate,         struct file_offer)
DEFINE_VAL_WRAPPER(val_mempool,            db_mempool_validate,            struct db_mempool_entry)
DEFINE_VAL_WRAPPER(val_onion_announcement, db_onion_announcement_validate, struct db_onion_announcement)
DEFINE_VAL_WRAPPER(val_peer,               db_peer_validate,               struct db_peer)
DEFINE_VAL_WRAPPER(val_store_product,      db_store_product_validate,      struct db_store_product)
DEFINE_VAL_WRAPPER(val_swap_contract,      db_swap_contract_validate,      struct swap_contract)
DEFINE_VAL_WRAPPER(val_store_order,        db_store_order_validate,        struct db_store_order)
DEFINE_VAL_WRAPPER(val_tx_index,           db_tx_validate,                 struct db_tx_index)
DEFINE_VAL_WRAPPER(val_utxo,               db_utxo_validate,               struct db_utxo)
DEFINE_VAL_WRAPPER(val_wallet_key,         db_wallet_key_validate,         struct db_wallet_key)
DEFINE_VAL_WRAPPER(val_sapling_key,        db_sapling_key_validate,        struct db_sapling_key)
DEFINE_VAL_WRAPPER(val_wallet_script,      db_wallet_script_validate,      struct db_wallet_script)
DEFINE_VAL_WRAPPER(val_wallet_tx,          db_wallet_tx_validate,          struct db_wallet_tx)
DEFINE_VAL_WRAPPER(val_wallet_utxo,        db_wallet_utxo_validate,        struct db_wallet_utxo)
DEFINE_VAL_WRAPPER(val_sapling_note,       db_sapling_note_validate,       struct db_sapling_note)
DEFINE_VAL_WRAPPER(val_zmsg,               db_zmsg_validate,               struct zmsg_message)
DEFINE_VAL_WRAPPER(val_znam_entry,         db_znam_entry_validate,         struct znam_entry)
DEFINE_VAL_WRAPPER(val_znam_text,          db_znam_text_validate,          struct znam_text_record)
DEFINE_VAL_WRAPPER(val_znam_addr,          db_znam_addr_validate,          struct znam_addr_record)
DEFINE_VAL_WRAPPER(val_zslp_balance,       db_zslp_balance_validate,       struct db_zslp_balance)
DEFINE_VAL_WRAPPER(val_zswap_ad,           db_zswap_ad_validate,           struct zswap_yardsale_ad)
DEFINE_VAL_WRAPPER(val_shop_want,          db_shop_want_validate,          struct shop_want)
DEFINE_VAL_WRAPPER(val_shop_fulfill,       db_shop_fulfill_validate,       struct shop_fulfill)
DEFINE_VAL_WRAPPER(val_zcode_science_plan, db_zcode_science_plan_validate, struct db_zcode_science_plan)
DEFINE_VAL_WRAPPER(val_yardsale_plan, db_yardsale_plan_validate, struct db_yardsale_plan)

#undef DEFINE_VAL_WRAPPER

/* zslp_token uses a private record struct.  We register the string-keyed
 * validator through its exported `db_zslp_token_validate_key` wrapper,
 * so the registry sees the token table without leaking the internal
 * record layout. */
static bool val_zslp_token(const void *row, char *err, size_t cap)
{
    struct ar_errors e; ar_errors_clear(&e);
    /* `row` is treated as a NUL-terminated token key string */
    db_zslp_token_validate_key((const char *)row, &e);
    return finish(&e, err, cap);
}

/* ── Meta: database status row ───────────────────────────────── *
 * The `database` meta-row has no persisted SQL table, but the plan
 * requires a validator entry.  We validate the runtime status struct.
 */
static bool val_database(const void *row, char *err, size_t cap)
{
    const struct node_db_status *s = (const struct node_db_status *)row;
    struct ar_errors e; ar_errors_clear(&e);
    if (!s) { ar_errors_add(&e, "status", "row is null"); return finish(&e, err, cap); }
    if (s->sync_batch_size < 0)
        ar_errors_add(&e, "sync_batch_size", "must be non-negative");
    if (s->sync_pending_blocks < 0)
        ar_errors_add(&e, "sync_pending_blocks", "must be non-negative");
    if (s->last_activity_time < 0)
        ar_errors_add(&e, "last_activity_time", "must be non-negative");
    return finish(&e, err, cap);
}

/* ── Master registrar ────────────────────────────────────────── */

void db_register_all_validators(void)
{
    /* Idempotent — re-registering replaces in-place. */
    db_register_validator("blocks",             val_block);
    db_register_validator("contacts",           val_contact);
    db_register_validator("file_offers",        val_file_offer);
    db_register_validator("file_services",      val_file_service);
    db_register_validator("mempool",            val_mempool);
    db_register_validator("onion_announcements", val_onion_announcement);
    db_register_validator("peers",              val_peer);
    db_register_validator("store_products",     val_store_product);
    db_register_validator("store_orders",       val_store_order);
    db_register_validator("zswp_contracts",     val_swap_contract);
    db_register_validator("tx_index",           val_tx_index);
    db_register_validator("utxos",              val_utxo);
    db_register_validator("wallet_keys",        val_wallet_key);
    db_register_validator("wallet_sapling_keys", val_sapling_key);
    db_register_validator("wallet_scripts",     val_wallet_script);
    db_register_validator("wallet_transactions", val_wallet_tx);
    db_register_validator("wallet_utxos",       val_wallet_utxo);
    db_register_validator("wallet_sapling_notes", val_sapling_note);
    db_register_validator("zmsg_messages",      val_zmsg);
    db_register_validator("znam_names",         val_znam_entry);
    db_register_validator("znam_text_records",  val_znam_text);
    db_register_validator("znam_addr_records",  val_znam_addr);
    db_register_validator("zslp_balances",      val_zslp_balance);
    db_register_validator("zslp_tokens",        val_zslp_token);
    db_register_validator("zswap_ads",          val_zswap_ad);
    db_register_validator("shop_wants",         val_shop_want);
    db_register_validator("shop_fulfills",      val_shop_fulfill);
    db_register_validator("zcode_science_plans", val_zcode_science_plan);
    db_register_validator("yardsale_plans",   val_yardsale_plan);
    db_register_validator("database",           val_database);
}
