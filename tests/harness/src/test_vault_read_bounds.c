/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Boundary and refusal tests for the vault read model
 * (contexts/wallet/services/src/vault_read.c), added to close gaps a
 * mutation sweep measured. The cases here exercise the paths that decide
 * whether a read model says "partial" or "answered": the identity caps, the
 * per-class saturation refusals, unreadable tables, allocation failures,
 * the argument refusals, and the wire names.
 *
 * Entry point: vault_read_bounds_tests(), called from test_vault_read().
 * Hermetic: every case runs against its own throwaway node.db with
 * synthetic zeroblob key material; nothing here spends or exports a key. */

#include "test_vault_read_fixture.h"

#include "config/runtime.h"
#include "json/json.h"

#define VB_KEY_CAP     512
#define VB_Z_CAP       256
#define VB_SWAP_CAP    512
#define VB_NAME_CAP    256
#define VB_OFFER_CAP   256
#define VB_TOKEN_CAP   64

int vault_read_bounds_tests(void);

/* ── argument refusals ────────────────────────────────────────────── */

static int vb_check_snapshot_refusals(void)
{
    struct vault_snapshot snap;
    struct node_db closed;
    struct zcl_result r;
    int failures = 0;

    memset(&closed, 0, sizeof(closed));
    memset(&snap, 0xFF, sizeof(snap));
    r = vault_read_snapshot(NULL, &snap);
    VRX_CHECK("NULL db is refused with code -2",
              !r.ok && r.code == -2 && strstr(r.message, "is NULL"));
    VRX_CHECK("a refused snapshot is zeroed, not stale",
              snap.zcl_total == 0 && snap.undetermined_classes == 0 &&
              !snap.rows[0].populated);
    r = vault_read_snapshot(&closed, &snap);
    VRX_CHECK("an unopened db is refused with code -2",
              !r.ok && r.code == -2 && strstr(r.message, "not open"));
    r = vault_read_snapshot(&closed, NULL);
    VRX_CHECK("a NULL out is refused with code -1",
              !r.ok && r.code == -1 && strstr(r.message, "NULL out"));
    return failures;
}

static int vb_check_json_refusals(void)
{
    struct vault_snapshot snap;
    struct json_value out;
    struct zcl_result r;
    int failures = 0;

    memset(&snap, 0, sizeof(snap));
    json_init(&out);
    r = vault_read_snapshot_to_json(NULL, &out);
    VRX_CHECK("a NULL snapshot is refused, code -1",
              !r.ok && r.code == -1 && strstr(r.message, "NULL snapshot"));
    r = vault_read_snapshot_to_json(&snap, NULL);
    VRX_CHECK("a NULL json out is refused, code -1",
              !r.ok && r.code == -1 && strstr(r.message, "NULL out"));
    json_free(&out);
    return failures;
}

static int vb_check_dump_state_without_db(void)
{
    struct json_value out;
    int failures = 0;

    VRX_CHECK("dump_state refuses a NULL out",
              !vault_read_dump_state_json(NULL, NULL));
    if (app_runtime_node_db() != NULL) {
        printf("vault_read: dump_state no-db case skipped (runtime db)\n");
        return failures;
    }
    json_init(&out);
    VRX_CHECK("dump_state still answers when no db is wired",
              vault_read_dump_state_json(&out, NULL));
    VRX_CHECK("it says available=false instead of reporting zero balances",
              json_get(&out, "available") != NULL &&
              !json_get_bool(json_get(&out, "available")));
    VRX_CHECK("and carries the snapshot error text",
              json_get_str(json_get(&out, "error")) != NULL &&
              strstr(json_get_str(json_get(&out, "error")), "node_db"));
    VRX_CHECK("with no balance rows to misread",
              json_get(&out, "classes") == NULL);
    json_free(&out);
    return failures;
}

/* ── identity caps ────────────────────────────────────────────────── */

static int vb_check_key_cap(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_keys")) {
        vrx_close(&f);
        return 1;
    }
    VRX_REQUIRE("512 wallet keys seeded", vrx_bulk_keys(&f.ndb, 0, VB_KEY_CAP));
    VRX_REQUIRE("512-key snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("exactly 512 keys fit and are not flagged truncated",
              !snap.identities.truncated &&
              snap.identities.transparent_keys == VB_KEY_CAP &&
              snap.identities.watch_only == 0);
    VRX_REQUIRE("a 513th key seeded", vrx_bulk_keys(&f.ndb, VB_KEY_CAP, 1));
    VRX_REQUIRE("513-key snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("the 513th key marks the identity set truncated",
              snap.identities.truncated &&
              snap.identities.transparent_keys == VB_KEY_CAP + 1);
    vrx_close(&f);
    return failures;
}

static int vb_check_watch_cap(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_watch")) {
        vrx_close(&f);
        return 1;
    }
    VRX_REQUIRE("512 watch-only rows seeded",
              vrx_bulk_watch(&f.ndb, 0, VB_KEY_CAP));
    VRX_REQUIRE("512-row snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("exactly 512 watch-only rows fit and are not truncated",
              !snap.identities.truncated &&
              snap.identities.watch_only == VB_KEY_CAP);
    VRX_CHECK("watch-only addresses alone are renderable: names determined",
              snap.rows[VAULT_CLASS_NAME].determined &&
              snap.rows[VAULT_CLASS_NAME].spendable == 0);
    VRX_REQUIRE("a 513th watch-only row seeded",
              vrx_bulk_watch(&f.ndb, VB_KEY_CAP, 1));
    VRX_REQUIRE("513-row snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("the 513th row is dropped and the set is flagged truncated",
              snap.identities.truncated &&
              snap.identities.watch_only == VB_KEY_CAP);
    vrx_close(&f);
    return failures;
}

static int vb_check_sapling_cap(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_sapling")) {
        vrx_close(&f);
        return 1;
    }
    VRX_REQUIRE("256 sapling keys seeded", vrx_bulk_sapling(&f.ndb, 0, VB_Z_CAP));
    VRX_REQUIRE("256-key snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("exactly 256 sapling keys fit and are not truncated",
              !snap.identities.truncated &&
              snap.identities.sapling_keys == VB_Z_CAP);
    VRX_REQUIRE("a 257th sapling key seeded",
              vrx_bulk_sapling(&f.ndb, VB_Z_CAP, 1));
    VRX_REQUIRE("257-key snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("the 257th key is dropped and the set is flagged truncated",
              snap.identities.truncated &&
              snap.identities.sapling_keys == VB_Z_CAP);
    vrx_close(&f);
    return failures;
}

static int vb_check_unreadable_identity_tables(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_unreadable")) {
        vrx_close(&f);
        return 1;
    }
    VRX_CHECK("a readable empty db has a complete identity set",
              vault_read_snapshot(&f.ndb, &snap).ok &&
              !snap.identities.truncated);

    VRX_REQUIRE("watch-only address column renamed",
              vrx_exec(&f.ndb, "ALTER TABLE wallet_watch_only RENAME COLUMN "
                               "address TO addr_x"));
    VRX_CHECK("an unreadable watch-only table flags the set truncated",
              vault_read_snapshot(&f.ndb, &snap).ok &&
              snap.identities.truncated);
    VRX_REQUIRE("watch-only address column restored",
              vrx_exec(&f.ndb, "ALTER TABLE wallet_watch_only RENAME COLUMN "
                               "addr_x TO address"));
    VRX_CHECK("a restored table is complete again",
              vault_read_snapshot(&f.ndb, &snap).ok &&
              !snap.identities.truncated);

    VRX_REQUIRE("sapling pk_d column renamed",
              vrx_exec(&f.ndb, "ALTER TABLE wallet_sapling_keys RENAME "
                               "COLUMN pk_d TO pkd_x"));
    VRX_CHECK("an unreadable sapling table flags the set truncated",
              vault_read_snapshot(&f.ndb, &snap).ok &&
              snap.identities.truncated);
    vrx_close(&f);
    return failures;
}

/* ── per-class saturation ─────────────────────────────────────────── */

static bool vb_seed_swaps(struct node_db *ndb, unsigned first, unsigned count)
{
    bool ok = true;

    for (unsigned i = first; ok && i < first + count; i++)
        ok = vrx_save_swap(ndb, i, SWAP_FUNDED, SWAP_CHAIN_ZCL, 1000,
                           "t1VaultStranger");
    return ok;
}

static int vb_check_swap_refused(const struct vault_snapshot *snap)
{
    const struct vault_row *r = &snap->rows[VAULT_CLASS_SWAP];
    int failures = 0;

    VRX_CHECK("512 contracts are refused as a partial total",
              !r->determined && r->populated &&
              strstr(r->reason, "512 or more swap contracts") &&
              r->encumbered == 0 && r->pending == 0 && r->spendable == 0 &&
              r->immature == 0 && r->item_count == 0 &&
              snap->zcl_encumbered == 0 && snap->zcl_total == 0 &&
              snap->undetermined_classes == 3);
    return failures;
}

static int vb_check_swap_cap(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    const struct vault_row *r = &snap.rows[VAULT_CLASS_SWAP];
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_swaps")) {
        vrx_close(&f);
        return 1;
    }
    VRX_REQUIRE("511 swap contracts seeded",
              vb_seed_swaps(&f.ndb, 0, VB_SWAP_CAP - 1));
    VRX_REQUIRE("511-swap snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("511 contracts still produce a determined total",
              r->determined && r->item_count == VB_SWAP_CAP - 1 &&
              r->encumbered == (VB_SWAP_CAP - 1) * 1000 &&
              strstr(r->reason, "511 live ZCL HTLC(s) of 511 rows") &&
              snap.undetermined_classes == 2);
    VRX_REQUIRE("a 512th contract seeded", vb_seed_swaps(&f.ndb, VB_SWAP_CAP - 1, 1));
    VRX_REQUIRE("512-swap snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    failures += vb_check_swap_refused(&snap);
    vrx_close(&f);
    return failures;
}

static int vb_check_name_cap(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    const struct vault_row *r = &snap.rows[VAULT_CLASS_NAME];
    uint8_t hash[20];
    char addr[64];
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_names")) {
        vrx_close(&f);
        return 1;
    }
    vrx_key_hash(hash, 9001);
    VRX_REQUIRE("owner key and address derived",
              vrx_add_key(&f.ndb, hash) &&
              vrx_key_addr(hash, addr, sizeof(addr)));
    for (unsigned i = 0; i < VB_NAME_CAP - 1; i++)
        if (!vrx_save_name(&f.ndb, i, addr))
            failures++;
    VRX_REQUIRE("255 names saved under the owner (no save failed)", failures == 0);
    VRX_REQUIRE("255-name snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("255 names are counted exactly",
              r->determined && r->spendable == VB_NAME_CAP - 1 &&
              r->item_count == VB_NAME_CAP - 1 &&
              strstr(r->reason, "matched against 1 identities"));
    VRX_REQUIRE("a 256th name saved", vrx_save_name(&f.ndb, VB_NAME_CAP - 1, addr));
    VRX_REQUIRE("256-name snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("256 names under one address are refused as partial",
              !r->determined && r->populated &&
              strstr(r->reason, "one address owns 256 or more names") &&
              r->spendable == 0 && r->item_count == 0);
    vrx_close(&f);
    return failures;
}

static void vb_fill_z(uint8_t z[43])
{
    for (size_t i = 0; i < 43; i++)
        z[i] = (uint8_t)(0x41 + i);
}

static int vb_check_offer_cap(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    const struct vault_row *r = &snap.rows[VAULT_CLASS_MARKET];
    uint8_t z[43], zero[43];
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_offers")) {
        vrx_close(&f);
        return 1;
    }
    vb_fill_z(z);
    memset(zero, 0, sizeof(zero));
    VRX_REQUIRE("one sapling key seeded",
              vrx_add_sapling(&f.ndb, 0, z, 11, z + 11, 32));
    VRX_REQUIRE("the matching offer saved", vrx_save_offer(&f.ndb, 0, z, 9000));
    for (unsigned i = 1; i < VB_OFFER_CAP - 1; i++)
        if (!vrx_save_offer(&f.ndb, i, zero, 100 + i))
            failures++;
    VRX_REQUIRE("255 offers saved in total (no save failed)", failures == 0);
    VRX_REQUIRE("255-offer snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("255 offers are counted, one of them ours",
              r->determined && r->spendable == 1 && r->item_count == 1 &&
              strstr(r->reason, "1 of 255 gossiped offers name one of our 1 "
                                "z-addresses"));
    VRX_REQUIRE("a 256th offer saved",
              vrx_save_offer(&f.ndb, VB_OFFER_CAP - 1, zero, 50));
    VRX_REQUIRE("256-offer snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("a full offer cache is refused as a partial count",
              !r->determined && r->populated &&
              strstr(r->reason, "offer cache saturated at 256 rows") &&
              r->spendable == 0 && r->item_count == 0);
    vrx_close(&f);
    return failures;
}

/* An all-zero Sapling key must not match a zero-filled slot past the end
 * of the offer list: the only offer names a different address. */
static int vb_check_zero_identity_offer(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    uint8_t z[43], zero[43];
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_zeroid")) {
        vrx_close(&f);
        return 1;
    }
    vb_fill_z(z);
    memset(zero, 0, sizeof(zero));
    VRX_REQUIRE("an all-zero sapling key seeded",
              vrx_add_sapling(&f.ndb, 0, zero, 11, zero + 11, 32));
    VRX_REQUIRE("one offer naming another address saved",
              vrx_save_offer(&f.ndb, 0, z, 100));
    VRX_REQUIRE("snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("no offer is ours, and nothing past the list is read",
              snap.rows[VAULT_CLASS_MARKET].determined &&
              snap.rows[VAULT_CLASS_MARKET].item_count == 0 &&
              snap.rows[VAULT_CLASS_MARKET].spendable == 0);
    vrx_close(&f);
    return failures;
}

/* ── allocation failure ───────────────────────────────────────────── */

static int vb_check_allocation_failures(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    struct zcl_result r;
    uint8_t hash[20], z[43];
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_alloc")) {
        vrx_close(&f);
        return 1;
    }
    vb_fill_z(z);
    vrx_key_hash(hash, 9002);
    VRX_REQUIRE("a key and a sapling key seeded",
              vrx_add_key(&f.ndb, hash) &&
              vrx_add_sapling(&f.ndb, 0, z, 11, z + 11, 32));

    zcl_alloc_fault_fail_next("vault_znam");
    VRX_CHECK("snapshot survives a names allocation failure",
              vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("the names row says so instead of reporting zero",
              !snap.rows[VAULT_CLASS_NAME].determined &&
              strstr(snap.rows[VAULT_CLASS_NAME].reason,
                     "allocation for 256 znam rows failed"));

    zcl_alloc_fault_fail_next("vault_swaps");
    VRX_CHECK("snapshot survives a swap allocation failure",
              vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("the swap row says so instead of reporting zero",
              !snap.rows[VAULT_CLASS_SWAP].determined &&
              strstr(snap.rows[VAULT_CLASS_SWAP].reason,
                     "allocation for 512 swap contracts failed"));

    zcl_alloc_fault_fail_next("vault_offers");
    VRX_CHECK("snapshot survives an offer allocation failure",
              vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("the market row says so instead of reporting zero",
              !snap.rows[VAULT_CLASS_MARKET].determined &&
              strstr(snap.rows[VAULT_CLASS_MARKET].reason,
                     "allocation for 256 file offers failed"));

    zcl_alloc_fault_fail_next("vault_identities");
    r = vault_read_snapshot(&f.ndb, &snap);
    VRX_CHECK("an identity allocation failure refuses the whole snapshot",
              !r.ok && r.code == -3 &&
              strstr(r.message, "identity set allocation"));
    zcl_alloc_fault_clear();
    vrx_close(&f);
    return failures;
}

/* ── tokens ───────────────────────────────────────────────────────── */

/* The held token of vb_check_token_states, once it has a definition and
 * then once the definition table cannot be read. */
static int vb_check_token_defined_phases(struct node_db *ndb)
{
    struct vault_snapshot snap;
    const struct vault_row *r = &snap.rows[VAULT_CLASS_TOKEN];
    int failures = 0;

    VRX_STOP("the definition is saved", vrx_token_meta(ndb, 1));
    VRX_STOP("snapshot builds with the definition",
              vault_read_snapshot(ndb, &snap).ok);
    VRX_CHECK("cursor 0 is a folded height: the row is determined",
              r->determined && r->item_count == 1 &&
              strstr(r->reason, "1 token IDs held") &&
              strstr(r->reason, "folded through h=0") &&
              snap.token_items[0].metadata_available &&
              strcmp(snap.token_items[0].ticker, "TK1") == 0 &&
              strcmp(snap.token_items[0].name, "Vault Token 1") == 0 &&
              snap.token_items[0].decimals == 2);

    VRX_STOP("definition table made unreadable",
              vrx_exec(ndb, "ALTER TABLE zslp_tokens RENAME COLUMN "
                            "ticker TO tk_x"));
    VRX_STOP("snapshot builds with unreadable definitions",
              vault_read_snapshot(ndb, &snap).ok);
    VRX_CHECK("a failed definition lookup is counted as a failure",
              !r->determined &&
              strstr(r->reason, "0 held token definitions missing and 1 "
                                "metadata lookups failed"));
    return failures;
}

static int vb_check_token_states(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    const struct vault_row *r = &snap.rows[VAULT_CLASS_TOKEN];
    uint8_t hash[20];
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_tokstate")) {
        vrx_close(&f);
        return 1;
    }
    vrx_key_hash(hash, 9003);
    VRX_REQUIRE("owner key and one held token seeded",
              vrx_add_key(&f.ndb, hash) &&
              vrx_ledger_row(&f.ndb, 1, 1, 77, hash));

    VRX_REQUIRE("snapshot builds with no cursor",
              vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("an unbuilt projection is undetermined, never a zero",
              !r->determined && strstr(r->reason, "cursor=-1") &&
              r->item_count == 0 && snap.token_item_count == 0);

    VRX_REQUIRE("cursor moved to height 0",
              node_db_state_set_int(&f.ndb, "zslp_ledger_cursor_height", 0));
    VRX_REQUIRE("snapshot builds at cursor 0",
              vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("a held token with no definition makes the row undetermined",
              !r->determined && r->item_count == 1 &&
              strstr(r->reason, "1 held token definitions missing and 0 "
                                "metadata lookups failed") &&
              snap.token_item_count == 1 && snap.token_items[0].units == 77 &&
              !snap.token_items[0].metadata_available);

    failures += vb_check_token_defined_phases(&f.ndb);
    vrx_close(&f);
    return failures;
}

static bool vb_seed_tokens(struct node_db *ndb, const uint8_t owner[20],
                           unsigned first, unsigned count)
{
    bool ok = true;

    for (unsigned i = first; ok && i < first + count; i++)
        ok = vrx_ledger_row(ndb, i, i, 5, owner) && vrx_token_meta(ndb, i);
    return ok;
}

static int vb_check_token_cap(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    const struct vault_row *r = &snap.rows[VAULT_CLASS_TOKEN];
    uint8_t hash[20];
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_tokcap")) {
        vrx_close(&f);
        return 1;
    }
    vrx_key_hash(hash, 9004);
    VRX_REQUIRE("owner key, cursor and 64 defined tokens seeded",
              vrx_add_key(&f.ndb, hash) &&
              node_db_state_set_int(&f.ndb, "zslp_ledger_cursor_height", 1) &&
              vb_seed_tokens(&f.ndb, hash, 1, VB_TOKEN_CAP));
    VRX_REQUIRE("64-token snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("exactly 64 tokens fit without truncation",
              r->determined && !snap.token_items_truncated &&
              snap.token_item_count == VB_TOKEN_CAP &&
              r->item_count == VB_TOKEN_CAP);
    VRX_REQUIRE("a 65th token seeded",
              vb_seed_tokens(&f.ndb, hash, VB_TOKEN_CAP + 1, 1));
    VRX_REQUIRE("65-token snapshot builds", vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("a 65th token truncates the list and the row says so",
              !r->determined && snap.token_items_truncated &&
              snap.token_item_count == VB_TOKEN_CAP &&
              r->item_count == VB_TOKEN_CAP &&
              strstr(r->reason, "more than 64 distinct tokens"));
    vrx_close(&f);
    return failures;
}

/* ── identity-set honesty ─────────────────────────────────────────── */

/* 513 keys overflow the 512-slot identity set. The watch-only count must
 * not go negative, and every class that joins against the set must say
 * the set is incomplete instead of reporting a determined count. */
static int vb_check_identity_overflow(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_overflow")) {
        vrx_close(&f);
        return 1;
    }
    VRX_REQUIRE("513 wallet keys seeded",
                vrx_bulk_keys(&f.ndb, 0, VB_KEY_CAP + 1));
    VRX_REQUIRE("one watch-only row seeded",
                vrx_add_watch(&f.ndb, 9100, "t1VaultOverflowWatch"));
    VRX_REQUIRE("overflow snapshot builds",
                vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("the watch-only count is never negative",
              snap.identities.truncated && snap.identities.watch_only >= 0);
    VRX_CHECK("an incomplete identity set makes the names row undetermined",
              !snap.rows[VAULT_CLASS_NAME].determined &&
              strstr(snap.rows[VAULT_CLASS_NAME].reason,
                     "identity set is incomplete") &&
              snap.rows[VAULT_CLASS_NAME].spendable == 0);
    vrx_close(&f);
    return failures;
}

static int vb_check_unreadable_watch_names(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    uint8_t hash[20];
    char addr[64];
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_watchnames")) {
        vrx_close(&f);
        return 1;
    }
    vrx_key_hash(hash, 9101);
    VRX_REQUIRE("owner key, address and one name seeded",
                vrx_add_key(&f.ndb, hash) &&
                vrx_key_addr(hash, addr, sizeof(addr)) &&
                vrx_save_name(&f.ndb, 0, addr));
    VRX_REQUIRE("watch-only address column renamed",
                vrx_exec(&f.ndb, "ALTER TABLE wallet_watch_only RENAME "
                                 "COLUMN address TO addr_x"));
    VRX_REQUIRE("snapshot builds with an unreadable watch-only table",
                vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("an unreadable watch-only table leaves names undetermined",
              !snap.rows[VAULT_CLASS_NAME].determined &&
              strstr(snap.rows[VAULT_CLASS_NAME].reason,
                     "identity set is incomplete"));
    vrx_close(&f);
    return failures;
}

static int vb_check_sapling_overflow_market(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_zover")) {
        vrx_close(&f);
        return 1;
    }
    VRX_REQUIRE("257 sapling keys seeded",
                vrx_bulk_sapling(&f.ndb, 0, VB_Z_CAP + 1));
    VRX_REQUIRE("sapling overflow snapshot builds",
                vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("an incomplete sapling set makes the market row undetermined",
              snap.identities.truncated &&
              !snap.rows[VAULT_CLASS_MARKET].determined &&
              strstr(snap.rows[VAULT_CLASS_MARKET].reason,
                     "identity set is incomplete"));
    vrx_close(&f);
    return failures;
}

/* A watch-only row that repeats a wallet key's address is one identity:
 * the names it owns are counted once. */
static int vb_check_watch_duplicates_key(void)
{
    struct vrx_fix f;
    struct vault_snapshot snap;
    uint8_t hash[20];
    char addr[64];
    int failures = 0;

    if (!vrx_open(&f, "vault_bounds_dupwatch")) {
        vrx_close(&f);
        return 1;
    }
    vrx_key_hash(hash, 9102);
    VRX_REQUIRE("owner key, address, watch copy and two names seeded",
                vrx_add_key(&f.ndb, hash) &&
                vrx_key_addr(hash, addr, sizeof(addr)) &&
                vrx_add_watch(&f.ndb, 9102, addr) &&
                vrx_save_name(&f.ndb, 0, addr) &&
                vrx_save_name(&f.ndb, 1, addr));
    VRX_REQUIRE("duplicate-identity snapshot builds",
                vault_read_snapshot(&f.ndb, &snap).ok);
    VRX_CHECK("two names under one address count as two, not four",
              snap.rows[VAULT_CLASS_NAME].determined &&
              snap.rows[VAULT_CLASS_NAME].spendable == 2 &&
              snap.rows[VAULT_CLASS_NAME].item_count == 2 &&
              snap.identities.transparent_keys == 1 &&
              snap.identities.watch_only == 1);
    vrx_close(&f);
    return failures;
}

/* ── wire names ───────────────────────────────────────────────────── */

static int vb_check_wire_names(void)
{
    static const char *const cls[] = {
        "transparent_zcl", "shielded_zcl", "zslp_tokens", "znam_names",
        "swap_encumbered", "file_market_offers",
    };
    static const char *const unit[] = {
        "zatoshi", "zatoshi", "token_base_units", "names", "zatoshi",
        "offers",
    };
    static const char *const ev[] = {
        "unknown", "exact_wallet_utxo_sum", "exact_note_sum",
        "exact_ledger_unspent", "exact_owner_address_match",
        "exact_contract_state", "heuristic_payment_address_match",
    };
    int failures = 0;

    for (int i = 0; i < 6; i++) {
        VRX_CHECK("class wire name",
                  strcmp(vault_class_name((enum vault_class)i), cls[i]) == 0);
        VRX_CHECK("class unit",
                  strcmp(vault_class_unit((enum vault_class)i), unit[i]) == 0);
    }
    for (int i = 0; i < 7; i++)
        VRX_CHECK("evidence wire name",
                  strcmp(vault_evidence_name((enum vault_evidence)i),
                         ev[i]) == 0);
    VRX_CHECK("an out-of-range class is named unknown, with unit unknown",
              strcmp(vault_class_name(VAULT_CLASS_COUNT), "unknown") == 0 &&
              strcmp(vault_class_unit(VAULT_CLASS_COUNT), "unknown") == 0);
    return failures;
}

int vault_read_bounds_tests(void)
{
    int failures = 0;

    failures += vb_check_snapshot_refusals();
    failures += vb_check_json_refusals();
    failures += vb_check_dump_state_without_db();
    failures += vb_check_wire_names();
    failures += vb_check_unreadable_identity_tables();
    failures += vb_check_key_cap();
    failures += vb_check_watch_cap();
    failures += vb_check_sapling_cap();
    failures += vb_check_swap_cap();
    failures += vb_check_name_cap();
    failures += vb_check_offer_cap();
    failures += vb_check_zero_identity_offer();
    failures += vb_check_allocation_failures();
    failures += vb_check_token_states();
    failures += vb_check_token_cap();
    failures += vb_check_identity_overflow();
    failures += vb_check_unreadable_watch_names();
    failures += vb_check_sapling_overflow_market();
    failures += vb_check_watch_duplicates_key();
    return failures;
}
