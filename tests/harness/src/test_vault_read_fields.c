/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Field-value tests for the vault read model
 * (contexts/wallet/services/src/vault_read.c), added to close gaps a
 * mutation sweep measured. One populated fixture puts a distinct, non-zero
 * value in every column of every class, so a reply field that is dropped,
 * swapped or zeroed cannot hide behind a coincidental zero; a second, bare
 * fixture pins the "no identity" and "undetermined" shapes. The JSON reply
 * is then held to the struct it was rendered from, key by key.
 *
 * Entry point: vault_read_fields_tests(), called from test_vault_read().
 * Hermetic: a throwaway node.db per case, synthetic zeroblob key material,
 * no spend and no key export. */

#include "test_vault_read_fixture.h"

#include "core/uint256.h"
#include "json/json.h"

int vault_read_fields_tests(void);

/* The fixture's own transparent identity, shared by seeding and checks. */
struct vf_ctx {
    uint8_t k1[20];
    char    e1[64];        /* base58 address of k1 */
    char    w3[64];        /* a 63-character watch-only address */
    uint8_t z[43];         /* the sapling key's raw payment address */
};

static void vf_ctx_init(struct vf_ctx *c)
{
    memset(c, 0, sizeof(*c));
    vrx_key_hash(c->k1, 7001);
    (void)vrx_key_addr(c->k1, c->e1, sizeof(c->e1));
    c->w3[0] = 't';
    memset(c->w3 + 1, 'W', 62);
    for (size_t i = 0; i < sizeof(c->z); i++)
        c->z[i] = (uint8_t)(0x41 + i);
}

/* ── seeding ──────────────────────────────────────────────────────── */

static bool vf_seed_identities(struct node_db *ndb, const struct vf_ctx *c)
{
    uint8_t short_div[10], short_pkd[31];

    memset(short_div, 0x61, sizeof(short_div));
    memset(short_pkd, 0x62, sizeof(short_pkd));
    return vrx_add_key(ndb, c->k1) &&
           vrx_add_watch(ndb, 7101, "t1VaultWatchOne") &&
           vrx_add_watch(ndb, 7102, "x") &&
           vrx_add_watch(ndb, 7103, c->w3) &&
           vrx_add_watch(ndb, 7104, "") &&
           vrx_add_sapling(ndb, 1, c->z, 11, c->z + 11, 32) &&
           vrx_add_sapling(ndb, 2, short_div, sizeof(short_div),
                           c->z + 11, 32) &&
           vrx_add_sapling(ndb, 3, c->z, 11, short_pkd, sizeof(short_pkd));
}

static bool vf_seed_utxo(struct node_db *ndb, uint8_t tag, int64_t value,
                         const uint8_t owner[20], bool coinbase, bool spent)
{
    uint8_t txid[32], sp[32];
    char th[65], sh[65], oh[41], spent_sql[80];

    memset(txid, 0x21, sizeof(txid));
    memset(sp, 0x22, sizeof(sp));
    txid[0] = tag;
    vrx_hex(th, txid, 32);
    vrx_hex(sh, sp, 32);
    vrx_hex(oh, owner, 20);
    snprintf(spent_sql, sizeof(spent_sql), "%s%s%s", spent ? "X'" : "NULL",
             spent ? sh : "", spent ? "'" : "");
    return vrx_exec(ndb,
        "INSERT INTO wallet_utxos(txid,vout,value,address_hash,script,"
        "height,spent_txid,spent_vin,is_coinbase) VALUES(X'%s',0,%lld,"
        "X'%s',X'51',3,%s,0,%d)",
        th, (long long)value, oh, spent_sql, coinbase ? 1 : 0);
}

static bool vf_seed_note(struct node_db *ndb, uint8_t tag, int64_t value,
                         bool spent)
{
    uint8_t txid[32], nf[32];
    char th[65], nh[65], spent_sql[80];

    memset(txid, 0x23, sizeof(txid));
    memset(nf, 0x24, sizeof(nf));
    txid[0] = tag;
    nf[0] = tag;
    vrx_hex(th, txid, 32);
    vrx_hex(nh, nf, 32);
    snprintf(spent_sql, sizeof(spent_sql), "%s%s%s", spent ? "X'" : "NULL",
             spent ? th : "", spent ? "'" : "");
    return vrx_exec(ndb,
        "INSERT INTO wallet_sapling_notes(txid,output_index,value,rcm,ivk,"
        "diversifier,pk_d,cm,nullifier,block_height,spent_txid) VALUES("
        "X'%s',0,%lld,zeroblob(32),zeroblob(32),zeroblob(11),zeroblob(32),"
        "zeroblob(32),X'%s',10,%s)",
        th, (long long)value, nh, spent_sql);
}

static bool vf_seed_money(struct node_db *ndb, const struct vf_ctx *c)
{
    return vf_seed_utxo(ndb, 1, 5000, c->k1, false, false) &&
           vf_seed_utxo(ndb, 2, 700, c->k1, true, false) &&
           vf_seed_utxo(ndb, 3, 90000, c->k1, false, true) &&
           vf_seed_note(ndb, 1, 3000, false) &&
           vf_seed_note(ndb, 2, 80000, true);
}

static bool vf_seed_swaps(struct node_db *ndb, const struct vf_ctx *c)
{
    return vrx_save_swap(ndb, 1, SWAP_FUNDED, SWAP_CHAIN_ZCL, 1000, c->e1) &&
           vrx_save_swap(ndb, 2, SWAP_PENDING, SWAP_CHAIN_ZCL, 20,
                         "t1VaultWatchOne") &&
           vrx_save_swap(ndb, 3, SWAP_EXPIRED, SWAP_CHAIN_ZCL, 300, c->w3) &&
           vrx_save_swap(ndb, 4, SWAP_FUNDED, SWAP_CHAIN_BTC, 7777,
                         "t1StrangerBtc") &&
           vrx_save_swap(ndb, 5, SWAP_FUNDED, SWAP_CHAIN_ZCL, 4,
                         "t1Stranger") &&
           vrx_save_swap(ndb, 6, SWAP_REDEEMED, SWAP_CHAIN_ZCL, 55555, c->e1) &&
           vrx_save_swap(ndb, 7, SWAP_REFUNDED, SWAP_CHAIN_ZCL, 66666, c->e1) &&
           vrx_save_swap(ndb, 8, SWAP_PENDING, SWAP_CHAIN_ZCL, 1, "x");
}

static bool vf_seed_names(struct node_db *ndb, const struct vf_ctx *c)
{
    return vrx_save_name(ndb, 0, c->e1) && vrx_save_name(ndb, 1, c->e1) &&
           vrx_save_name(ndb, 2, "t1VaultWatchOne") &&
           vrx_save_name(ndb, 3, "t1Stranger") &&
           vrx_save_name(ndb, 4, "x");
}

static bool vf_seed_offers(struct node_db *ndb, const struct vf_ctx *c)
{
    uint8_t last_flipped[43], div_flipped[43], zero[43];

    memcpy(last_flipped, c->z, 43);
    memcpy(div_flipped, c->z, 43);
    memset(zero, 0, sizeof(zero));
    last_flipped[42] ^= 0x01;
    div_flipped[10] ^= 0x01;
    return vrx_save_offer(ndb, 0, c->z, 5000) &&
           vrx_save_offer(ndb, 1, last_flipped, 4000) &&
           vrx_save_offer(ndb, 2, div_flipped, 3500) &&
           vrx_save_offer(ndb, 3, zero, 3000);
}

static bool vf_seed_tokens(struct node_db *ndb, const struct vf_ctx *c)
{
    return vrx_ledger_row(ndb, 1, 11, 700, c->k1) &&
           vrx_ledger_row(ndb, 1, 12, 300, c->k1) &&
           vrx_ledger_row(ndb, 2, 13, 9, c->k1) &&
           vrx_token_meta(ndb, 1) && vrx_token_meta(ndb, 2) &&
           node_db_state_set_int(ndb, "zslp_ledger_cursor_height", 1);
}

static bool vf_seed_all(struct node_db *ndb, const struct vf_ctx *c)
{
    return vf_seed_identities(ndb, c) && vf_seed_money(ndb, c) &&
           vf_seed_swaps(ndb, c) && vf_seed_names(ndb, c) &&
           vf_seed_offers(ndb, c) && vf_seed_tokens(ndb, c);
}

/* ── expected values, per class ───────────────────────────────────── */

static bool vf_row_head(const struct vault_row *r, const char *cls,
                        const char *unit, bool money, const char *source)
{
    return r->populated && r->determined && strcmp(r->class_name, cls) == 0 &&
           strcmp(r->unit, unit) == 0 && r->is_money == money &&
           r->source_primitive && strcmp(r->source_primitive, source) == 0;
}

static int vf_check_rich_identities(const struct vault_snapshot *s)
{
    int failures = 0;

    VRX_CHECK("one key, three counted watch-only rows, one good sapling key",
              s->identities.transparent_keys == 1 &&
              s->identities.watch_only == 3 &&
              s->identities.sapling_keys == 1 && !s->identities.truncated);
    return failures;
}

static int vf_check_rich_money_rows(const struct vault_snapshot *s)
{
    const struct vault_row *t = &s->rows[VAULT_CLASS_TRANSPARENT];
    const struct vault_row *z = &s->rows[VAULT_CLASS_SHIELDED];
    int failures = 0;

    VRX_CHECK("transparent row: spendable, immature and unspent count",
              vf_row_head(t, "transparent_zcl", "zatoshi", true,
                          "db_wallet_utxo_spendable_balance + "
                          "db_wallet_utxo_balance_with_count") &&
              t->evidence == VAULT_EVIDENCE_EXACT_WALLET_UTXO_SUM &&
              t->spendable == 5000 && t->immature == 700 &&
              t->pending == 0 && t->encumbered == 0 && t->item_count == 2 &&
              strstr(t->reason, "immature = raw unspent sum minus"));
    VRX_CHECK("shielded row: only the unspent note counts",
              vf_row_head(z, "shielded_zcl", "zatoshi", true,
                          "db_sapling_note_balance_with_count") &&
              z->evidence == VAULT_EVIDENCE_EXACT_NOTE_SUM &&
              z->spendable == 3000 && z->immature == 0 &&
              z->item_count == 1 &&
              strstr(z->reason, "a row exists only for a note this node "
                                "decrypted"));
    return failures;
}

static int vf_check_rich_swap_row(const struct vault_snapshot *s)
{
    const struct vault_row *w = &s->rows[VAULT_CLASS_SWAP];
    int failures = 0;

    VRX_CHECK("swap row: funded+expired encumbered, pending apart, live count",
              vf_row_head(w, "swap_encumbered", "zatoshi", true,
                          "db_swap_list") &&
              w->evidence == VAULT_EVIDENCE_EXACT_CONTRACT_STATE &&
              w->encumbered == 1304 && w->pending == 21 &&
              w->spendable == 0 && w->immature == 0 && w->item_count == 5);
    VRX_CHECK("swap note counts foreign-chain and unmatched rows exactly",
              strstr(w->reason, "5 live ZCL HTLC(s) of 8 rows; 1 on other "
                                "chains (different unit, excluded); 2 "
                                "my_address not in the local identity set"));
    return failures;
}

static int vf_check_rich_name_market_rows(const struct vault_snapshot *s)
{
    const struct vault_row *n = &s->rows[VAULT_CLASS_NAME];
    const struct vault_row *m = &s->rows[VAULT_CLASS_MARKET];
    int failures = 0;

    VRX_CHECK("names row: owned names over key and watch-only addresses",
              vf_row_head(n, "znam_names", "names", false,
                          "db_znam_list_by_owner") &&
              n->evidence == VAULT_EVIDENCE_EXACT_OWNER_ADDRESS_MATCH &&
              n->spendable == 4 && n->item_count == 4 &&
              strstr(n->reason, "owner_address matched against 4 "
                                "identities"));
    VRX_CHECK("market row: only the exact payee match counts",
              vf_row_head(m, "file_market_offers", "offers", false,
                          "db_file_offer_list") &&
              m->evidence == VAULT_EVIDENCE_HEURISTIC_PAYMENT_ADDRESS_MATCH &&
              m->spendable == 1 && m->item_count == 1 &&
              strstr(m->reason, "1 of 4 gossiped offers name one of our 1 "
                                "z-addresses as payee"));
    return failures;
}

static int vf_check_rich_token_row(const struct vault_snapshot *s)
{
    const struct vault_row *t = &s->rows[VAULT_CLASS_TOKEN];
    int failures = 0;

    VRX_CHECK("token row: two separate holdings, determined",
              vf_row_head(t, "zslp_tokens", "token_base_units", false,
                          "zslp_ledger_wallet_tokens") &&
              t->evidence == VAULT_EVIDENCE_EXACT_LEDGER_UNSPENT &&
              t->item_count == 2 && t->spendable == 0 &&
              strstr(t->reason, "2 token IDs held; balances remain "
                                "separate; projection folded through h=1"));
    VRX_CHECK("token items carry units, utxo counts and metadata",
              s->token_item_count == 2 && !s->token_items_truncated &&
              s->token_items[0].units == 1000 &&
              s->token_items[0].utxo_count == 2 &&
              s->token_items[1].units == 9 &&
              s->token_items[1].utxo_count == 1 &&
              s->token_items[0].metadata_available &&
              s->token_items[1].metadata_available);
    return failures;
}

static int vf_check_rich_totals(const struct vault_snapshot *s)
{
    int failures = 0;

    VRX_CHECK("the zcl rollup sums only the money classes",
              s->zcl_spendable == 8000 && s->zcl_pending == 21 &&
              s->zcl_immature == 700 && s->zcl_encumbered == 1304 &&
              s->zcl_total == 10025);
    VRX_CHECK("every class is determined, none counted undetermined",
              s->undetermined_classes == 0);
    return failures;
}

/* ── json parity ──────────────────────────────────────────────────── */

static bool vf_str_is(const struct json_value *j, const char *key,
                      const char *want)
{
    const struct json_value *v = json_get(j, key);

    return v && v->type == JSON_STR && want && strcmp(json_get_str(v), want) == 0;
}

static bool vf_int_is(const struct json_value *j, const char *key, int64_t want)
{
    const struct json_value *v = json_get(j, key);

    return v && v->type == JSON_INT && json_get_int(v) == want;
}

static bool vf_bool_is(const struct json_value *j, const char *key, bool want)
{
    const struct json_value *v = json_get(j, key);

    return v && v->type == JSON_BOOL && json_get_bool(v) == want;
}

static bool vf_row_json_strings(const struct vault_row *r,
                                const struct json_value *j)
{
    const char *key   = r->determined ? "note" : "reason";
    const char *other = r->determined ? "reason" : "note";

    return vf_str_is(j, "class", r->class_name) &&
           vf_str_is(j, "unit", r->unit) &&
           vf_str_is(j, "evidence", vault_evidence_name(r->evidence)) &&
           vf_str_is(j, "source_primitive",
                     r->source_primitive ? r->source_primitive : "") &&
           vf_str_is(j, key, r->reason) && json_get(j, other) == NULL;
}

static bool vf_row_json_numbers(const struct vault_row *r,
                                const struct json_value *j)
{
    return vf_bool_is(j, "is_money", r->is_money) &&
           vf_bool_is(j, "determined", r->determined) &&
           vf_int_is(j, "spendable", r->spendable) &&
           vf_int_is(j, "pending", r->pending) &&
           vf_int_is(j, "immature", r->immature) &&
           vf_int_is(j, "encumbered", r->encumbered) &&
           vf_int_is(j, "item_count", r->item_count);
}

static bool vf_token_item_ids(const struct vault_token_item *t,
                              const struct json_value *j)
{
    struct uint256 id;
    char hex[65];

    memcpy(id.data, t->token_id, 32);
    uint256_get_hex(&id, hex);
    return vf_str_is(j, "id", hex) && vf_int_is(j, "units", t->units) &&
           vf_int_is(j, "utxo_count", t->utxo_count) &&
           vf_bool_is(j, "encumbered", false);
}

static bool vf_token_item_meta(const struct vault_token_item *t,
                               const struct json_value *j)
{
    return vf_bool_is(j, "metadata_available", t->metadata_available) &&
           vf_str_is(j, "ticker", t->ticker) &&
           vf_str_is(j, "name", t->name) &&
           vf_int_is(j, "decimals", t->decimals);
}

static int vf_check_token_json(const struct vault_snapshot *s,
                               const struct json_value *token_json)
{
    const struct json_value *items = json_get(token_json, "items");
    bool ok = items && items->type == JSON_ARR &&
              json_size(items) == s->token_item_count &&
              vf_bool_is(token_json, "items_truncated", false);
    int failures = 0;

    for (size_t i = 0; ok && i < s->token_item_count; i++)
        ok = vf_token_item_ids(&s->token_items[i], json_at(items, i)) &&
             vf_token_item_meta(&s->token_items[i], json_at(items, i));
    VRX_CHECK("token json items match the struct, field for field", ok);
    return failures;
}

static int vf_check_totals_json(const struct vault_snapshot *s,
                                const struct json_value *out)
{
    const struct json_value *zcl = json_get(out, "zcl");
    const struct json_value *ids = json_get(out, "identities");
    int failures = 0;

    VRX_CHECK("zcl rollup block matches the struct, unit zatoshi",
              zcl && vf_int_is(zcl, "spendable", s->zcl_spendable) &&
              vf_int_is(zcl, "pending", s->zcl_pending) &&
              vf_int_is(zcl, "immature", s->zcl_immature) &&
              vf_int_is(zcl, "encumbered", s->zcl_encumbered) &&
              vf_int_is(zcl, "total", s->zcl_total) &&
              vf_str_is(zcl, "unit", "zatoshi"));
    VRX_CHECK("identities block matches the struct",
              ids && vf_int_is(ids, "transparent_keys",
                               s->identities.transparent_keys) &&
              vf_int_is(ids, "watch_only", s->identities.watch_only) &&
              vf_int_is(ids, "sapling_keys", s->identities.sapling_keys) &&
              vf_bool_is(ids, "truncated", s->identities.truncated));
    VRX_CHECK("class_count and undetermined_classes are reported",
              vf_int_is(out, "class_count", VAULT_CLASS_COUNT) &&
              vf_int_is(out, "undetermined_classes",
                        s->undetermined_classes));
    return failures;
}

static int vf_check_json_parity(const struct vault_snapshot *s)
{
    struct json_value out;
    const struct json_value *classes;
    bool rows_ok = true;
    int failures = 0;

    json_init(&out);
    VRX_CHECK("snapshot renders to json",
              vault_read_snapshot_to_json(s, &out).ok);
    classes = json_get(&out, "classes");
    VRX_CHECK("json holds one entry per class",
              classes && json_size(classes) == VAULT_CLASS_COUNT);
    for (size_t i = 0; classes && i < VAULT_CLASS_COUNT; i++) {
        const struct json_value *row = json_at(classes, i);
        rows_ok = rows_ok && vf_row_json_strings(&s->rows[i], row) &&
                  vf_row_json_numbers(&s->rows[i], row);
    }
    VRX_CHECK("every json row matches its struct row, key for key", rows_ok);
    if (classes && json_size(classes) == VAULT_CLASS_COUNT)
        failures += vf_check_token_json(
            s, json_at(classes, VAULT_CLASS_TOKEN));
    failures += vf_check_totals_json(s, &out);
    json_free(&out);
    return failures;
}

/* ── the two fixtures ─────────────────────────────────────────────── */

static int vf_check_rich_snapshot(void)
{
    struct vrx_fix f;
    struct vf_ctx c;
    struct vault_snapshot s;
    int failures = 0;

    if (!vrx_open(&f, "vault_fields_rich")) {
        vrx_close(&f);
        return 1;
    }
    vf_ctx_init(&c);
    VRX_REQUIRE("the owner's address text derived", c.e1[0] != '\0');
    VRX_REQUIRE("the populated fixture is seeded", vf_seed_all(&f.ndb, &c));
    VRX_REQUIRE("populated snapshot builds", vault_read_snapshot(&f.ndb, &s).ok);
    failures += vf_check_rich_identities(&s);
    failures += vf_check_rich_money_rows(&s);
    failures += vf_check_rich_swap_row(&s);
    failures += vf_check_rich_name_market_rows(&s);
    failures += vf_check_rich_token_row(&s);
    failures += vf_check_rich_totals(&s);
    failures += vf_check_json_parity(&s);
    vrx_close(&f);
    return failures;
}

static int vf_check_bare_snapshot(void)
{
    struct vrx_fix f;
    struct vault_snapshot s;
    const struct vault_row *n = &s.rows[VAULT_CLASS_NAME];
    int failures = 0;

    if (!vrx_open(&f, "vault_fields_bare")) {
        vrx_close(&f);
        return 1;
    }
    VRX_REQUIRE("bare snapshot builds", vault_read_snapshot(&f.ndb, &s).ok);
    VRX_CHECK("a node with no identity holds no names, and says why",
              n->determined && n->spendable == 0 && n->item_count == 0 &&
              n->evidence == VAULT_EVIDENCE_EXACT_OWNER_ADDRESS_MATCH &&
              strstr(n->reason, "no transparent identity"));
    VRX_CHECK("undetermined rows carry zero amounts and a reason",
              !s.rows[VAULT_CLASS_TOKEN].determined &&
              !s.rows[VAULT_CLASS_MARKET].determined &&
              s.rows[VAULT_CLASS_TOKEN].reason[0] != '\0' &&
              s.rows[VAULT_CLASS_MARKET].reason[0] != '\0' &&
              s.rows[VAULT_CLASS_MARKET].spendable == 0 &&
              s.rows[VAULT_CLASS_MARKET].pending == 0 &&
              s.rows[VAULT_CLASS_MARKET].immature == 0 &&
              s.rows[VAULT_CLASS_MARKET].encumbered == 0);
    VRX_CHECK("exactly the two undeterminable classes are counted",
              s.undetermined_classes == 2 && s.zcl_total == 0);
    failures += vf_check_json_parity(&s);
    vrx_close(&f);
    return failures;
}

int vault_read_fields_tests(void)
{
    int failures = 0;

    failures += vf_check_rich_snapshot();
    failures += vf_check_bare_snapshot();
    return failures;
}
