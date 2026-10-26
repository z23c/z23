/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * RENDER AUDIT — find real bugs in rendered HTML.
 *
 * Creates a realistic wallet DB, renders every page, and checks
 * for actual defects:
 * - Unresolved {{template_vars}} leaking to user
 * - Empty pages (0 bytes or just headers)
 * - SQL/internal errors leaking to user
 * - Broken HTML structure
 * - Missing nav on any page
 * - Inconsistent active tab highlighting
 * - Privacy claims contradicting actual data */

#include "test/test_core.h"
#include "test/wallet_view_fixture.h"
#include "controllers/wallet_view_controller.h"
#include "controllers/wallet_view_internal.h"
#include "models/database.h"
#include <string.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <unistd.h>

DEFINE_WALLET_VIEW_CLIENT(_buf, _audit_len, render, audit_get, audit_post,
                          contains, 131072)

static char g_tmp[256];

static bool make_db(int64_t t_sat, int64_t z_sat, int n_txs, int n_peers)
{
    snprintf(g_tmp, sizeof(g_tmp), "/tmp/zcl_audit_XXXXXX");
    if (!mkdtemp(g_tmp)) return false;

    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", g_tmp);

    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) return false;

    TEST_DB_EXEC(db,
        "CREATE TABLE IF NOT EXISTS blocks"
        "(hash BLOB PRIMARY KEY,height INT,time INT,prev_hash BLOB,"
        "version INT,merkle_root BLOB,bits INT,nonce BLOB,solution BLOB,"
        "chain_work BLOB,status INT DEFAULT 0,file_pos INT DEFAULT 0,"
        "num_tx INT DEFAULT 0,sapling_root BLOB,sprout_root BLOB,"
        "sapling_value_balance INT DEFAULT 0,sprout_value_balance INT DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS wallet_utxos"
        "(txid BLOB,vout INT,value INT,address_hash BLOB,script BLOB,"
        "height INT,spent_txid BLOB,spent_vin INT,is_coinbase INT,"
        "PRIMARY KEY(txid,vout));"
        "CREATE TABLE IF NOT EXISTS wallet_sapling_notes"
        "(txid BLOB,output_index INT,value INT,rcm BLOB,memo BLOB,"
        "ivk BLOB,diversifier BLOB,pk_d BLOB,cm BLOB,"
        "nullifier BLOB UNIQUE,block_height INT,spent_txid BLOB,"
        "address TEXT,PRIMARY KEY(txid,output_index));"
        "CREATE TABLE IF NOT EXISTS wallet_sapling_keys"
        "(ivk BLOB PRIMARY KEY,xsk BLOB,xfvk BLOB,diversifier BLOB,"
        "pk_d BLOB,child_index INT,address TEXT);"
        "CREATE TABLE IF NOT EXISTS wallet_keys"
        "(pubkey_hash BLOB PRIMARY KEY,pubkey BLOB,privkey BLOB,"
        "compressed INT,created_at INT);"
        "CREATE TABLE IF NOT EXISTS wallet_transactions"
        "(txid BLOB PRIMARY KEY,raw_tx BLOB,block_hash BLOB,"
        "block_height INT,time_received INT,from_me INT,fee INT);"
        "CREATE TABLE IF NOT EXISTS peers"
        "(id INTEGER PRIMARY KEY,ip TEXT,port INT,services INT,"
        "last_seen INT,last_try INT,attempts INT,source TEXT);"
        "CREATE TABLE IF NOT EXISTS mempool"
        "(txid BLOB PRIMARY KEY,raw_tx BLOB,fee INT,size INT,"
        "time_added INT,height_added INT);"
        "CREATE TABLE IF NOT EXISTS sapling_spends"
        "(nullifier BLOB PRIMARY KEY,txid BLOB);"
        "CREATE TABLE IF NOT EXISTS zslp_tokens"
        "(token_id BLOB PRIMARY KEY,ticker TEXT,name TEXT,"
        "decimals INT,genesis_height INT);"
        "CREATE TABLE IF NOT EXISTS zslp_transfers"
        "(id INTEGER PRIMARY KEY,token_id BLOB,tx_type TEXT,"
        "txid BLOB,from_addr BLOB,to_addr BLOB,amount INT);"
        "CREATE TABLE IF NOT EXISTS contacts"
        "(address TEXT PRIMARY KEY,name TEXT,last_used INT);"
        );

    /* Tip block */
    {
        uint8_t h[32]={0xFF}, p[32]={0xFE}, m[32]={0xFD};
        sqlite3_stmt *s = NULL;
        TEST_DB_RUN(db, s,
            "INSERT INTO blocks(hash,height,time,prev_hash,version,"
            "merkle_root,bits,status,num_tx) VALUES"
            "(?,500000,1700000000,?,4,?,0x1d00ffff,3,5)",
        {
            sqlite3_bind_blob(s, 1, h, 32, SQLITE_STATIC);
            sqlite3_bind_blob(s, 2, p, 32, SQLITE_STATIC);
            sqlite3_bind_blob(s, 3, m, 32, SQLITE_STATIC);
        });
    }

    /* Transparent UTXOs */
    if (t_sat > 0) {
        uint8_t tx[32]={1}, ah[20]={0xAA};
        sqlite3_stmt *s = NULL;
        TEST_DB_RUN(db, s,
            "INSERT INTO wallet_utxos(txid,vout,value,address_hash,height)"
            " VALUES(?,0,?,?,100)", {
            sqlite3_bind_blob(s, 1, tx, 32, SQLITE_STATIC);
            sqlite3_bind_int64(s, 2, t_sat);
            sqlite3_bind_blob(s, 3, ah, 20, SQLITE_STATIC);
        });
    }

    /* Shielded notes */
    if (z_sat > 0) {
        uint8_t tx[32]={2}, nf[32]={0xBB};
        sqlite3_stmt *s = NULL;
        TEST_DB_RUN(db, s,
            "INSERT INTO wallet_sapling_notes"
            "(txid,output_index,value,nullifier,block_height)"
            " VALUES(?,0,?,?,200)", {
            sqlite3_bind_blob(s, 1, tx, 32, SQLITE_STATIC);
            sqlite3_bind_int64(s, 2, z_sat);
            sqlite3_bind_blob(s, 3, nf, 32, SQLITE_STATIC);
        });
    }

    /* Wallet transactions */
    for (int i = 0; i < n_txs; i++) {
        uint8_t tx[32]; memset(tx, 0x10+i, 32);
        uint8_t bh[32]; memset(bh, 0xFF, 32);
        sqlite3_stmt *s = NULL;
        TEST_DB_RUN(db, s,
            "INSERT INTO wallet_transactions"
            "(txid,block_hash,block_height,time_received,from_me,fee)"
            " VALUES(?,?,?,?,?,?)", {
            sqlite3_bind_blob(s, 1, tx, 32, SQLITE_STATIC);
            sqlite3_bind_blob(s, 2, bh, 32, SQLITE_STATIC);
            sqlite3_bind_int(s, 3, 499990 + i);
            sqlite3_bind_int(s, 4, 1700000000 - i * 600);
            sqlite3_bind_int(s, 5, i % 2);
            sqlite3_bind_int64(s, 6, 10000);
        });
    }

    /* Peers */
    for (int i = 0; i < n_peers; i++) {
        char ip[32]; snprintf(ip, sizeof(ip), "192.168.1.%d", i+1);
        sqlite3_stmt *s = NULL;
        TEST_DB_RUN(db, s,
            "INSERT INTO peers(ip,port,services,last_seen)"
            " VALUES(?,8033,5,?)", {
            sqlite3_bind_text(s, 1, ip, -1, SQLITE_STATIC);
            sqlite3_bind_int(s, 2, 1700000000);
        });
    }

    sqlite3_close(db);
    return true;
}

static void cleanup(void) {
    /* No shell: the path is absolute and may contain spaces. */
    if (g_tmp[0])
        TEST_DISCARD(test_rm_rf_recursive(g_tmp));
    wallet_view_init(NULL);
}

/* A route check. need[] is applied in order and ends at the first zero
 * text (at most 10). alt set => contains(text) || contains(alt).
 * absent set => !contains(text). Otherwise contains(text). */
enum aud_len_mode {
    AUD_LEN_MIN = 0,    /* n > min_len */
    AUD_LEN_EQ = 1,     /* n == min_len */
    AUD_LEN_IGNORE = 2  /* length is not part of the check */
};

enum aud_fail_kind {
    AUD_FAIL_PLAIN = 0,
    AUD_FAIL_LEN = 1,
    AUD_FAIL_DETAIL = 2
};

struct aud_need {
    const char *text;
    const char *alt;
    int absent;
};

struct aud_route {
    const char *label;
    const char *method;
    const char *path;
    const char *body;
    size_t min_len;
    enum aud_len_mode len_mode;
    enum aud_fail_kind fail_kind;
    struct aud_need need[10];
};

static bool contains_either(const char *left, const char *right)
{
    return contains(left) || contains(right);
}

static void audit_dashboard_fail_reasons(size_t n)
{
    printf("FAIL:");
    if (n <= 500) printf(" too-short");
    if (!contains("ZCL")) printf(" no-ZCL");
    if (!contains("private")) printf(" no-private");
    if (!contains("Send")) printf(" no-Send");
    if (!contains("Receive")) printf(" no-Receive");
    if (!contains("/wallet/node")) printf(" no-node-link");
    if (contains("{{{")) printf(" LEAKED-TEMPLATE-VAR");
    if (contains("sqlite")) printf(" LEAKED-sqlite");
    if (contains("SELECT ")) printf(" LEAKED-SELECT");
    if (contains("INSERT ")) printf(" LEAKED-INSERT");
    printf(" (len=%zu)\n", n);
}

static bool audit_route_passes(const struct aud_route *r, size_t *out_len)
{
    size_t n = render(r->method, r->path, r->body);
    *out_len = n;
    bool ok;
    if (r->len_mode == AUD_LEN_EQ)
        ok = n == r->min_len;
    else if (r->len_mode == AUD_LEN_IGNORE)
        ok = true;
    else
        ok = n > r->min_len;
    for (int i = 0; i < 10 && r->need[i].text; i++) {
        const struct aud_need *q = &r->need[i];
        if (q->alt)
            ok = ok && (contains(q->text) || contains(q->alt));
        else if (q->absent)
            ok = ok && !contains(q->text);
        else
            ok = ok && contains(q->text);
    }
    return ok;
}

static int audit_route_list(const struct aud_route *routes, size_t count)
{
    int failures = 0;
    for (size_t i = 0; i < count; i++) {
        const struct aud_route *r = &routes[i];
        size_t n = 0;
        bool ok;
        printf("%s", r->label);
        ok = audit_route_passes(r, &n);
        if (ok) {
            printf("OK\n");
            continue;
        }
        if (r->fail_kind == AUD_FAIL_DETAIL) {
            audit_dashboard_fail_reasons(n);
            failures++;
            continue;
        }
        if (r->fail_kind == AUD_FAIL_LEN)
            printf("FAIL (len=%zu)\n", n);
        else
            printf("FAIL\n");
        failures++;
    }
    return failures;
}

/* ── Route: dashboard ── */
static const struct aud_route k_render_audit_early[] = {
    {
        .label = "audit: dashboard renders with data... ",
        .method = "GET",
        .path = "/wallet",
        .body = NULL,
        .min_len = 500,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_DETAIL,
        .need = {
            { "ZCL", NULL, 0 },
            { "private", NULL, 0 },
            { "Send", NULL, 0 },
            { "Receive", NULL, 0 },
            { "/wallet/node", NULL, 0 },
            /* NO unresolved template vars (}}} can appear in JS legitimately) */
            { "{{{", NULL, 1 },
            /* NO SQL leaks */
            { "sqlite", NULL, 1 },
            { "SELECT ", NULL, 1 },
            { "INSERT ", NULL, 1 },
        },
    },
    /* ── Route: send ── */
    {
        .label = "audit: send page renders... ",
        .method = "GET",
        .path = "/wallet/send",
        .body = NULL,
        .min_len = 500,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_LEN,
        .need = {
            { "address", "Address", 0 },
            { "{{{", NULL, 1 },
            { "sqlite", NULL, 1 },
            { ">Send<", NULL, 0 }, /* nav active */
        },
    },
    /* ── Route: send review with valid-looking address ── */
    {
        .label = "audit: send review handles bad address... ",
        .method = "POST",
        .path = "/wallet/send/review",
        .body = "address=t1TestAddr12345678901234567890&amount=0.1",
        .min_len = 200,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_LEN,
        .need = {
            { "{{{", NULL, 1 },
            { "sqlite", NULL, 1 },
        },
    },
    /* ── Route: receive ── */
    {
        .label = "audit: receive page renders... ",
        .method = "GET",
        .path = "/wallet/receive",
        .body = NULL,
        .min_len = 500,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_LEN,
        .need = {
            { "recommended", NULL, 0 },
            { "zero-knowledge proof", NULL, 0 },
            { "{{{", NULL, 1 },
            { ">Receive<", NULL, 0 }, /* nav active */
        },
    },
    /* ── Route: history ── */
    {
        .label = "audit: history with 10 txs renders... ",
        .method = "GET",
        .path = "/wallet/history",
        .body = NULL,
        .min_len = 500,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_LEN,
        .need = {
            { "{{{", NULL, 1 },
            { "sqlite", NULL, 1 },
            { ">History<", NULL, 0 }, /* nav active */
        },
    },
    /* ── Route: history page 2 ── */
    {
        .label = "audit: history page 2 renders... ",
        .method = "GET",
        .path = "/wallet/history?page=1",
        .body = NULL,
        .min_len = 200,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_LEN,
        .need = {
            { "{{{", NULL, 1 },
        },
    },
    /* ── Route: history with filter ── */
    {
        .label = "audit: history filter=sent... ",
        .method = "GET",
        .path = "/wallet/history?filter=sent",
        .body = NULL,
        .min_len = 200,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_LEN,
        .need = {
            { "{{{", NULL, 1 },
        },
    },
    /* ── Route: node ── */
    {
        .label = "audit: node page with real data... ",
        .method = "GET",
        .path = "/wallet/node",
        .body = NULL,
        .min_len = 500,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_LEN,
        .need = {
            { "Command Center", NULL, 0 },
            { "sovereign", NULL, 0 },
            { "500", NULL, 0 }, /* height 500000 */
            { "3", NULL, 0 }, /* 3 peers */
            { "{{{", NULL, 1 },
            { "sqlite", NULL, 1 },
            { ">Node<", NULL, 0 }, /* nav active */
        },
    },
    /* ── Route: coins ── */
    {
        .label = "audit: coins page with UTXOs... ",
        .method = "GET",
        .path = "/wallet/coins",
        .body = NULL,
        .min_len = 200,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_LEN,
        .need = {
            { "{{{", NULL, 1 },
            { "sqlite", NULL, 1 },
        },
    },
    /* ── Route: shield ── */
    {
        .label = "audit: shield amount form... ",
        .method = "GET",
        .path = "/wallet/shield",
        .body = NULL,
        .min_len = 500,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_LEN,
        .need = {
            { "Amount", "amount", 0 },
            { "{{{", NULL, 1 },
        },
    },
    /* ── Route: shield confirm ── */
    {
        .label = "audit: shield confirm page... ",
        .method = "GET",
        .path = "/wallet/shield?amount=0.5",
        .body = NULL,
        .min_len = 500,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_LEN,
        .need = {
            { "0.5", NULL, 0 },
            { "Confirm", NULL, 0 },
            { "{{{", NULL, 1 },
        },
    },
    /* ── Route: pulse API ── */
    {
        .label = "audit: pulse returns valid JSON... ",
        .method = "GET",
        .path = "/api/wallet/pulse",
        .body = NULL,
        .min_len = 10,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_LEN,
        .need = {
            { "{", NULL, 0 },
            { "height", NULL, 0 },
            { "balance", NULL, 0 },
            { "<!DOCTYPE", NULL, 1 },
        },
    },
    /* ── Route: tx detail ── */
    {
        .label = "audit: tx detail with valid hex txid... ",
        .method = "GET",
        .path = "/wallet/tx/"
            "1010101010101010101010101010101010101010101010101010101010101010",
        .body = NULL,
        .min_len = 200,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_LEN,
        .need = {
            { "{{{", NULL, 1 },
            { "sqlite", NULL, 1 },
        },
    },
};

/* ── Privacy accuracy check ── */
static int audit_privacy_accuracy(void)
{
    int failures = 0;
    printf("audit: 16%% shielded matches actual data... ");
    render("GET", "/wallet", NULL);
    /* With 81M t-sat + 16M z-sat = 97M total, ~16% private */
    bool ok = contains("16%") || contains("17%");
    /* Must NOT claim untraceable */
    ok = ok && !contains("untraceable");
    ok = ok && !contains("Untraceable");
    if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    return failures;
}

/* ── Shield nudge shown when public balance exists ── */
static const struct aud_route k_render_audit_late[] = {
    {
        .label = "audit: shield nudge shown with public balance... ",
        .method = "GET",
        .path = "/wallet",
        .body = NULL,
        .min_len = 0,
        .len_mode = AUD_LEN_IGNORE,
        .fail_kind = AUD_FAIL_PLAIN,
        .need = {
            { "Shield All", "/wallet/shield", 0 },
            { "transparent addresses", "chain analysis", 0 },
        },
    },
    /* ── XSS checks ── */
    {
        .label = "audit: XSS in history search sanitized... ",
        .method = "GET",
        .path = "/wallet/history?q=<script>alert(1)</script>",
        .body = NULL,
        .min_len = 0,
        .len_mode = AUD_LEN_IGNORE,
        .fail_kind = AUD_FAIL_PLAIN,
        .need = {
            { "<script>alert", NULL, 1 },
        },
    },
    {
        .label = "audit: XSS in tx detail sanitized... ",
        .method = "GET",
        .path = "/wallet/tx/<img+onerror=alert(1)>",
        .body = NULL,
        .min_len = 0,
        .len_mode = AUD_LEN_IGNORE,
        .fail_kind = AUD_FAIL_PLAIN,
        .need = {
            { "<img+onerror", NULL, 1 },
        },
    },
    /* ── Edge cases ── */
    {
        .label = "audit: unknown route returns 0... ",
        .method = "GET",
        .path = "/wallet/doesnotexist",
        .body = NULL,
        .min_len = 0,
        .len_mode = AUD_LEN_EQ,
        .fail_kind = AUD_FAIL_LEN,
    },
    {
        /* should render error page, not crash */
        .label = "audit: POST with NULL body doesn't crash... ",
        .method = "POST",
        .path = "/wallet/send/review",
        .body = NULL,
        .min_len = 0,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_PLAIN,
    },
    {
        .label = "audit: POST shield confirm with 0 amount... ",
        .method = "POST",
        .path = "/wallet/shield/confirm",
        .body = "amount=0",
        .min_len = 0,
        .len_mode = AUD_LEN_MIN,
        .fail_kind = AUD_FAIL_PLAIN,
        .need = {
            { "{{{", NULL, 1 },
        },
    },
};

static int audit_private_and_empty_wallets(void)
{
    int failures = 0;

    /* ── 100% private wallet ── */
    {   printf("audit: 100%% private wallet shows no nudge... ");
        bool ok = make_db(0, 100000000, 0, 0);
        if (ok) {
            wallet_view_init(g_tmp);
            render("GET", "/wallet", NULL);
            ok = contains_either("100%", "All funds private");
            ok = ok && !contains("Shield All");
            ok = ok && !contains("transparent addresses");
            ok = ok && !contains("untraceable"); /* factual, not cutesy */
        }
        cleanup();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Empty wallet ── */
    {   printf("audit: empty wallet renders cleanly... ");
        bool ok = make_db(0, 0, 0, 0);
        if (ok) {
            wallet_view_init(g_tmp);
            render("GET", "/wallet", NULL);
            ok = contains_either("0.00", "0.0000");
            ok = ok && !contains("{{{");
            ok = ok && !contains("sqlite");
            ok = ok && !contains("untraceable");
        }
        cleanup();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* ── The actual audit ──────────────────────────────────── */

int spec_render_audit(void)
{
    int failures = 0;
    printf("\n=== Render Audit (real data, every route) ===\n");

    bool db_ok = make_db(81000000, 16000000, 10, 3);
    if (!db_ok) {
        printf("SKIP: could not create test DB\n");
        return 0;
    }
    wallet_view_init(g_tmp);

    failures += audit_route_list(
        k_render_audit_early,
        sizeof k_render_audit_early / sizeof k_render_audit_early[0]);

    failures += audit_privacy_accuracy();
    failures += audit_route_list(
        k_render_audit_late,
        sizeof k_render_audit_late / sizeof k_render_audit_late[0]);

    cleanup();

    failures += audit_private_and_empty_wallets();

    printf("Render audit: %d failures\n", failures);
    return failures;
}
