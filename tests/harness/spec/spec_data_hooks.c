/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Spec tests for ActiveRecord lifecycle hooks:
 * before_validate, after_validate, before_save, after_save,
 * before_destroy, after_destroy, async callbacks. */

#include "test/test_core.h"
#include "models/activerecord.h"
#include "models/block.h"
#include "models/wallet_key.h"
#include "models/database.h"
#include "event/event.h"
#include "keys/key.h"
#include "wallet/sapling_keys.h"
#include "wallet/wallet_sqlite.h"
#include <string.h>
#include <stdio.h>

static int g_wk_saved_fired;
static int g_sk_saved_fired;
static char g_wk_payload[EVENT_PAYLOAD_SIZE];

static void on_wallet_key_saved(enum event_type type, uint32_t peer_id,
                                 const void *payload, uint32_t payload_len,
                                 void *ctx)
{
    (void)type; (void)peer_id; (void)ctx;
    g_wk_saved_fired++;
    if (payload && payload_len > 0 && payload_len < EVENT_PAYLOAD_SIZE) {
        memcpy(g_wk_payload, payload, payload_len);
        g_wk_payload[payload_len] = '\0';
    }
}

static void on_sapling_key_saved(enum event_type type, uint32_t peer_id,
                                  const void *payload, uint32_t payload_len,
                                  void *ctx)
{
    (void)type; (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    g_sk_saved_fired++;
}

/* ── Test state ─────────────────────────────────────────── */

static int g_bv_count, g_av_count, g_bs_count, g_as_count;
static int g_bd_count, g_ad_count, g_async_s, g_async_d;

static bool hook_bv(void *r, void *c) { (void)r;(void)c; g_bv_count++; return true; }
static void hook_av(void *r, void *c) { (void)r;(void)c; g_av_count++; }
static bool hook_bs(void *r, void *c) { (void)r;(void)c; g_bs_count++; return true; }
static void hook_as(void *r, void *c) { (void)r;(void)c; g_as_count++; }
static bool hook_bd(void *r, void *c) { (void)r;(void)c; g_bd_count++; return true; }
static void hook_ad(void *r, void *c) { (void)r;(void)c; g_ad_count++; }
static void hook_as_async(void *r, size_t sz, void *c) { (void)r;(void)sz;(void)c; g_async_s++; }
static void hook_ad_async(void *r, size_t sz, void *c) { (void)r;(void)sz;(void)c; g_async_d++; }
static bool hook_reject(void *r, void *c) { (void)r;(void)c; return false; }

static void reset(void) {
    g_bv_count=0; g_av_count=0; g_bs_count=0; g_as_count=0;
    g_bd_count=0; g_ad_count=0; g_async_s=0; g_async_d=0;
}

int spec_data_hooks(void)
{
    int failures = 0;
    printf("\n=== ActiveRecord Lifecycle Hooks ===\n");

    {   printf("before_validate and after_validate fire... ");
        reset();
        struct ar_callbacks cb; ar_callbacks_init(&cb);
        ar_register_before_validate(&cb, hook_bv);
        ar_register_after_validate(&cb, hook_av);
        bool ok = ar_run_before_validate(&cb, NULL);
        ar_run_after_validate(&cb, NULL);
        ok = ok && g_bv_count == 1 && g_av_count == 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("before_validate halt stops validation... ");
        struct ar_callbacks cb; ar_callbacks_init(&cb);
        ar_register_before_validate(&cb, hook_reject);
        bool ok = !ar_run_before_validate(&cb, NULL);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("full lifecycle: validate → save → after fires... ");
        reset();
        struct ar_callbacks cb; ar_callbacks_init(&cb);
        ar_register_before_validate(&cb, hook_bv);
        ar_register_after_validate(&cb, hook_av);
        ar_register_before_save(&cb, hook_bs);
        ar_register_after_save(&cb, hook_as);
        ar_run_before_validate(&cb, NULL);
        ar_run_after_validate(&cb, NULL);
        ar_run_before_save(&cb, NULL);
        ar_run_after_save(&cb, NULL);
        bool ok = g_bv_count==1 && g_av_count==1 && g_bs_count==1 && g_as_count==1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("before_save halt does not affect validation... ");
        reset();
        struct ar_callbacks cb; ar_callbacks_init(&cb);
        ar_register_before_validate(&cb, hook_bv);
        ar_register_before_save(&cb, hook_reject);
        bool ok = ar_run_before_validate(&cb, NULL);
        ok = ok && !ar_run_before_save(&cb, NULL);
        ok = ok && g_bv_count == 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("before_destroy / after_destroy fire... ");
        reset();
        struct ar_callbacks cb; ar_callbacks_init(&cb);
        ar_register_before_destroy(&cb, hook_bd);
        ar_register_after_destroy(&cb, hook_ad);
        bool ok = ar_run_before_destroy(&cb, NULL);
        ar_run_after_destroy(&cb, NULL);
        ok = ok && g_bd_count==1 && g_ad_count==1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("after_save_async fires... ");
        reset();
        struct ar_callbacks cb; ar_callbacks_init(&cb);
        ar_register_after_save_async(&cb, hook_as_async);
        ar_run_after_save_async(&cb, NULL);
        bool ok = g_async_s == 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("after_destroy_async fires... ");
        reset();
        struct ar_callbacks cb; ar_callbacks_init(&cb);
        ar_register_after_destroy_async(&cb, hook_ad_async);
        ar_run_after_destroy_async(&cb, NULL);
        bool ok = g_async_d == 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("multiple before_save callbacks all run... ");
        reset();
        struct ar_callbacks cb; ar_callbacks_init(&cb);
        ar_register_before_save(&cb, hook_bs);
        ar_register_before_save(&cb, hook_bs);
        ar_register_before_save(&cb, hook_bs);
        ar_run_before_save(&cb, NULL);
        bool ok = g_bs_count == 3;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("callback overflow rejected... ");
        struct ar_callbacks cb; ar_callbacks_init(&cb);
        bool ok = true;
        for (int i = 0; i < AR_MAX_CALLBACKS; i++)
            ok = ok && ar_register_before_save(&cb, hook_bs);
        ok = ok && !ar_register_before_save(&cb, hook_bs);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("context pointer passed to callbacks... ");
        struct ar_callbacks cb; ar_callbacks_init(&cb);
        int ctx_val = 42;
        ar_callbacks_set_ctx(&cb, &ctx_val);
        bool ok = cb.ctx == &ctx_val;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("wallet_sqlite key write emits model.wallet_key_saved... ");
        event_log_init();
        event_clear_all_observers();
        g_wk_saved_fired = 0;
        g_sk_saved_fired = 0;
        memset(g_wk_payload, 0, sizeof(g_wk_payload));
        event_observe(EV_WALLET_KEY_SAVED, on_wallet_key_saved, NULL);
        event_observe(EV_SAPLING_KEY_SAVED, on_sapling_key_saved, NULL);

        /* The model save hook is gone — the encryption-aware single
         * writer (wallet_sqlite) owns the key-saved event feed. */
        struct node_db ndb;
        bool ok = node_db_open(&ndb, ":memory:");
        struct wallet_sqlite ws;
        ok = ok && wallet_sqlite_open(&ws, ndb.db);
        struct privkey key;
        struct pubkey pk;
        privkey_init(&key);
        memset(key.vch, 0xC3, 32);
        key.vch[1] = 0x3C;              /* keep it a valid scalar */
        key.fValid = true;
        key.fCompressed = true;
        ok = ok && privkey_get_pubkey(&key, &pk);
        ok = ok && wallet_sqlite_write_key(&ws, &pk, &key);
        ok = ok && g_wk_saved_fired == 1;
        ok = ok && strstr(g_wk_payload, "kind=transparent") != NULL;
        ok = ok && g_sk_saved_fired == 0;
        /* Rewrite of an existing row must NOT re-emit (once-per-key). */
        ok = ok && wallet_sqlite_write_key(&ws, &pk, &key);
        ok = ok && g_wk_saved_fired == 1;
        wallet_sqlite_close(&ws);
        node_db_close(&ndb);
        event_clear_all_observers();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("wallet_sqlite sapling write emits both events... ");
        event_log_init();
        event_clear_all_observers();
        g_wk_saved_fired = 0;
        g_sk_saved_fired = 0;
        memset(g_wk_payload, 0, sizeof(g_wk_payload));
        event_observe(EV_WALLET_KEY_SAVED, on_wallet_key_saved, NULL);
        event_observe(EV_SAPLING_KEY_SAVED, on_sapling_key_saved, NULL);

        struct node_db ndb;
        bool ok = node_db_open(&ndb, ":memory:");
        struct wallet_sqlite ws;
        ok = ok && wallet_sqlite_open(&ws, ndb.db);
        struct sapling_key_entry sk;
        memset(&sk, 0, sizeof(sk));
        memset(sk.ivk, 0xA1, 32);
        memset(&sk.xsk, 0xB2, sizeof(sk.xsk));
        memset(&sk.xfvk, 0xC3, sizeof(sk.xfvk));
        memset(sk.diversifier, 0xD4, 11);
        memset(sk.pk_d, 0xE5, 32);
        sk.child_index = 0;
        sk.used = true;
        ok = ok && wallet_sqlite_write_sapling_key(&ws, 0, &sk);
        ok = ok && g_wk_saved_fired == 1;
        ok = ok && strstr(g_wk_payload, "kind=sapling") != NULL;
        ok = ok && g_sk_saved_fired == 1;
        /* Rewrite of an existing row must NOT re-emit. */
        ok = ok && wallet_sqlite_write_sapling_key(&ws, 0, &sk);
        ok = ok && g_wk_saved_fired == 1;
        ok = ok && g_sk_saved_fired == 1;
        wallet_sqlite_close(&ws);
        node_db_close(&ndb);
        event_clear_all_observers();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("Data hooks: %d failures\n", failures);
    return failures;
}
