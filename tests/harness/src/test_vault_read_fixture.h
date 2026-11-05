/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Shared fixture helpers for the vault read mutation-closing tests
 * (test_vault_read_bounds.c, test_vault_read_fields.c). Every helper works
 * on a throwaway node.db under test-tmp/ with synthetic zeroblob key
 * material: no real wallet, no spend, no key export. */
#ifndef TEST_VAULT_READ_FIXTURE_H
#define TEST_VAULT_READ_FIXTURE_H

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "keys/key_io.h"
#include "models/database.h"
#include "models/file_offer.h"
#include "models/swap_contract.h"
#include "models/znam.h"
#include "models/zslp.h"
#include "script/standard.h"
#include "services/vault_read.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define VRX_CHECK(name, expr) do {                      \
    printf("vault_read: %s... ", (name));               \
    if ((expr)) { printf("OK\n"); }                     \
    else { printf("FAIL\n"); failures++; }              \
} while (0)

/* A zero-initialised fixture, so a teardown after an early return never
 * touches an unset path. */
struct vrx_fix {
    char          dir[256];
    char          path[320];
    struct node_db ndb;
    bool          opened;
};

static inline bool vrx_open(struct vrx_fix *f, const char *prefix)
{
    memset(f, 0, sizeof(*f));
    test_make_tmpdir(f->dir, sizeof(f->dir), prefix, "db");
    snprintf(f->path, sizeof(f->path), "%s/node.db", f->dir);
    f->opened = node_db_open(&f->ndb, f->path);
    if (!f->opened)
        printf("vault_read: node_db_open (%s)... FAIL\n", prefix);
    return f->opened;
}

static inline void vrx_close(struct vrx_fix *f)
{
    if (f->opened)
        node_db_close(&f->ndb);
    if (f->dir[0])
        test_rm_rf(f->dir);
    memset(f, 0, sizeof(*f));
}

static inline bool vrx_exec(struct node_db *ndb, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static inline bool vrx_exec(struct node_db *ndb, const char *fmt, ...)
{
    char sql[1024];
    char *err = NULL;
    va_list ap;
    int n, rc;

    va_start(ap, fmt);
    n = vsnprintf(sql, sizeof(sql), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(sql))
        return false;
    rc = sqlite3_exec(ndb->db, sql, NULL, NULL, &err);
    if (err) {
        printf("vault_read: fixture sql failed: %s\n", err);
        sqlite3_free(err);
    }
    return rc == SQLITE_OK;
}

static inline void vrx_hex(char *out, const uint8_t *b, size_t n)
{
    static const char digits[] = "0123456789abcdef";

    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = digits[b[i] >> 4];
        out[2 * i + 1] = digits[b[i] & 15];
    }
    out[2 * n] = '\0';
}

/* A hash160 that is unique per `n` and never ends in a zero byte. */
static inline void vrx_key_hash(uint8_t h[20], unsigned n)
{
    memset(h, 0xC3, 20);
    h[0] = (uint8_t)(n >> 16);
    h[1] = (uint8_t)(n >> 8);
    h[2] = (uint8_t)n;
}

/* The base58 P2PKH text of a hash160 under the active chain params: the
 * exact encoding vault_read uses for its own identities. */
static inline bool vrx_key_addr(const uint8_t hash[20], char *out, size_t sz)
{
    struct tx_destination dest;
    const struct chain_params *cp = chain_params_get();
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *pk = chain_params_base58_prefix(
        cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc = chain_params_base58_prefix(
        cp, B58_SCRIPT_ADDRESS, &sc_len);

    memset(&dest, 0, sizeof(dest));
    dest.type = DEST_KEY_ID;
    memcpy(dest.id.key.id.data, hash, 20);
    return encode_destination(&dest, pk, pk_len, sc, sc_len, out, sz);
}

static inline bool vrx_add_key(struct node_db *ndb, const uint8_t hash[20])
{
    char hex[41];

    vrx_hex(hex, hash, 20);
    return vrx_exec(ndb,
        "INSERT INTO wallet_keys(pubkey_hash,pubkey,privkey,compressed,"
        "created_at) VALUES(X'%s',zeroblob(33),zeroblob(32),1,0)", hex);
}

/* Keys [first, first+count) in one transaction. */
static inline bool vrx_bulk_keys(struct node_db *ndb, unsigned first,
                                 unsigned count)
{
    bool ok = vrx_exec(ndb, "BEGIN");

    for (unsigned i = first; ok && i < first + count; i++) {
        uint8_t h[20];
        vrx_key_hash(h, i);
        ok = vrx_add_key(ndb, h);
    }
    return vrx_exec(ndb, ok ? "COMMIT" : "ROLLBACK") && ok;
}

static inline bool vrx_add_watch(struct node_db *ndb, unsigned n,
                                 const char *address)
{
    uint8_t h[20];
    char hex[41];

    vrx_key_hash(h, n);
    h[3] = 0x77;
    vrx_hex(hex, h, 20);
    return vrx_exec(ndb,
        "INSERT INTO wallet_watch_only(address_hash,address,created_at)"
        " VALUES(X'%s','%s',0)", hex, address);
}

static inline bool vrx_bulk_watch(struct node_db *ndb, unsigned first,
                                  unsigned count)
{
    bool ok = vrx_exec(ndb, "BEGIN");

    for (unsigned i = first; ok && i < first + count; i++) {
        char addr[40];
        snprintf(addr, sizeof(addr), "t1VaultWatch%06u", i);
        ok = vrx_add_watch(ndb, i, addr);
    }
    return vrx_exec(ndb, ok ? "COMMIT" : "ROLLBACK") && ok;
}

/* One sapling key row with the given diversifier (11) and pk_d (32); the
 * lengths of the two blobs are the caller's, so a malformed row can be
 * seeded on purpose. */
static inline bool vrx_add_sapling(struct node_db *ndb, unsigned n,
                                   const uint8_t *div, size_t div_len,
                                   const uint8_t *pkd, size_t pkd_len)
{
    char ivk[65], dh[64], ph[80];
    uint8_t ivk_raw[32];

    memset(ivk_raw, 0x5E, sizeof(ivk_raw));
    ivk_raw[0] = (uint8_t)(n >> 8);
    ivk_raw[1] = (uint8_t)n;
    vrx_hex(ivk, ivk_raw, 32);
    vrx_hex(dh, div, div_len);
    vrx_hex(ph, pkd, pkd_len);
    return vrx_exec(ndb,
        "INSERT INTO wallet_sapling_keys(ivk,xsk,xfvk,diversifier,pk_d,"
        "child_index) VALUES(X'%s',zeroblob(1),zeroblob(1),X'%s',X'%s',%u)",
        ivk, dh, ph, n);
}

static inline bool vrx_bulk_sapling(struct node_db *ndb, unsigned first,
                                    unsigned count)
{
    uint8_t div[11], pkd[32];
    bool ok = vrx_exec(ndb, "BEGIN");

    memset(div, 0x44, sizeof(div));
    memset(pkd, 0x45, sizeof(pkd));
    for (unsigned i = first; ok && i < first + count; i++)
        ok = vrx_add_sapling(ndb, i, div, sizeof(div), pkd, sizeof(pkd));
    return vrx_exec(ndb, ok ? "COMMIT" : "ROLLBACK") && ok;
}


/* ── typed rows through the model layer ───────────────────────────── */

static inline bool vrx_save_swap(struct node_db *ndb, unsigned n,
                                 enum swap_state st, enum swap_chain chain,
                                 int64_t amount, const char *my_address)
{
    struct swap_contract sc;

    memset(&sc, 0, sizeof(sc));
    snprintf(sc.swap_id, sizeof(sc.swap_id), "%064x", n);
    sc.role  = SWAP_INITIATOR;
    sc.state = st;
    sc.chain = chain;
    memset(sc.secret_hash, 0xA5, sizeof(sc.secret_hash));
    sc.amount   = amount;
    sc.locktime = 3200000;
    snprintf(sc.my_address, sizeof(sc.my_address), "%s", my_address);
    snprintf(sc.counter_address, sizeof(sc.counter_address),
             "t1VaultCounterparty");
    sc.redeem_script[0]  = 0x63;
    sc.redeem_script_len = 1;
    snprintf(sc.p2sh_address, sizeof(sc.p2sh_address), "t3VaultHtlc%06u", n);
    sc.created_at = 1700000000 + (int64_t)n;
    return db_swap_save(ndb, &sc);
}

/* A ZNAM name unique per idx ("naaa", "naab", ...), owned by `owner`. */
static inline bool vrx_save_name(struct node_db *ndb, unsigned idx,
                                 const char *owner)
{
    struct znam_entry e;

    memset(&e, 0, sizeof(e));
    e.name[0] = 'n';
    e.name[1] = (char)('a' + (idx / 676) % 26);
    e.name[2] = (char)('a' + (idx / 26) % 26);
    e.name[3] = (char)('a' + idx % 26);
    snprintf(e.owner_address, sizeof(e.owner_address), "%s", owner);
    e.target_type = ZNAM_TYPE_ONION;
    snprintf(e.target_value, sizeof(e.target_value), "%s.onion", e.name);
    memset(e.reg_txid, 0x5A, sizeof(e.reg_txid));
    e.reg_txid[0] = (uint8_t)idx;
    e.reg_txid[1] = (uint8_t)(idx >> 8);
    memcpy(e.last_update_txid, e.reg_txid, sizeof(e.last_update_txid));
    e.reg_height = 10;
    e.expiry_height = 5000;
    return db_znam_save(ndb, &e);
}

/* A free legacy offer paying `z_addr`. peer_ip[0] is non-zero on purpose:
 * it sits directly after z_addr in the struct, so a comparison that reads
 * one byte too far sees it. */
static inline bool vrx_save_offer(struct node_db *ndb, unsigned idx,
                                  const uint8_t z_addr[43], int64_t last_seen)
{
    struct file_offer o;

    memset(&o, 0, sizeof(o));
    memset(o.root_hash, 0x6B, sizeof(o.root_hash));
    o.root_hash[0] = (uint8_t)idx;
    o.root_hash[1] = (uint8_t)(idx >> 8);
    snprintf(o.filename, sizeof(o.filename), "vault-offer-%u", idx);
    o.size_bytes = 1;
    o.num_chunks = 1;
    memcpy(o.z_addr, z_addr, 43);
    o.peer_ip[0]   = 1;
    o.peer_port    = 1;
    o.last_seen    = last_seen;
    o.ttl          = 1;
    return db_file_offer_save(ndb, &o);
}

static inline void vrx_token_id(uint8_t t[32], unsigned n)
{
    memset(t, 0x11, 32);
    t[0] = (uint8_t)n;
    t[1] = (uint8_t)(n >> 8);
}

/* One unspent ledger row of token `n`, paid to `owner` (a wallet key). */
static inline bool vrx_ledger_row(struct node_db *ndb, unsigned n,
                                  unsigned txn, int64_t amount,
                                  const uint8_t owner[20])
{
    uint8_t tok[32], txid[32];
    char th[65], xh[65], oh[41];

    vrx_token_id(tok, n);
    memset(txid, 0x31, sizeof(txid));
    txid[0] = (uint8_t)txn;
    txid[1] = (uint8_t)(txn >> 8);
    vrx_hex(th, tok, 32);
    vrx_hex(xh, txid, 32);
    vrx_hex(oh, owner, 20);
    return vrx_exec(ndb,
        "INSERT INTO zslp_ledger(token_id,txid,vout,amount,address,"
        "created_height,role) VALUES(X'%s',X'%s',1,%lld,X'%s',1,1)",
        th, xh, (long long)amount, oh);
}

static inline bool vrx_token_meta(struct node_db *ndb, unsigned n)
{
    uint8_t tok[32];
    char ticker[16], name[32];

    vrx_token_id(tok, n);
    snprintf(ticker, sizeof(ticker), "TK%u", n);
    snprintf(name, sizeof(name), "Vault Token %u", n);
    return db_zslp_token_save(ndb, tok, ticker, name, 2, "", 1, 1000);
}

#endif
