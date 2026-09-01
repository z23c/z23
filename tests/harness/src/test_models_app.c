/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Focused app-model tests. */

#include "test/test_core.h"
#include "models/peer.h"
#include "models/contact.h"
#include "models/onion_announcement.h"
#include "models/store.h"
#include "models/file_service.h"
#include "models/swap_contract.h"
#include "models/zmsg.h"
#include "models/hodl_wave.h"
#include "models/wallet_label.h"
#include <unistd.h>

int test_model_app(void)
{
    int failures = 0;

    printf("SwapContract model rejects an empty record and accepts a valid one... ");
    {
        struct swap_contract bad, good;
        struct ar_errors e;

        memset(&bad, 0, sizeof(bad));
        ar_errors_clear(&e);
        bool ok = !db_swap_contract_validate(&bad, &e) && ar_errors_any(&e);

        memset(&good, 0, sizeof(good));
        snprintf(good.swap_id, sizeof(good.swap_id), "%s",
                 "deadbeef00112233445566778899aabbccddeeff0011223344556677889900");
        good.role = SWAP_INITIATOR;
        good.state = SWAP_PENDING;
        good.chain = SWAP_CHAIN_ZCL;
        memset(good.secret_hash, 0xAB, sizeof(good.secret_hash));
        good.amount = 100000;
        good.locktime = 500000;
        snprintf(good.my_address, sizeof(good.my_address), "%s", "t1MyAddress");
        snprintf(good.counter_address, sizeof(good.counter_address), "%s",
                 "t1CounterAddress");
        good.redeem_script_len = 97;
        snprintf(good.p2sh_address, sizeof(good.p2sh_address), "%s", "t3P2shAddress");
        good.created_at = 1700000000;
        ar_errors_clear(&e);
        ok = ok && db_swap_contract_validate(&good, &e) && !ar_errors_any(&e);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("SwapContract model rejects a non-hex swap_id and a zero amount... ");
    {
        struct swap_contract swap;
        struct ar_errors e;

        memset(&swap, 0, sizeof(swap));
        snprintf(swap.swap_id, sizeof(swap.swap_id), "%s", "NOT-HEX-ID");
        swap.role = SWAP_INITIATOR;
        swap.state = SWAP_PENDING;
        swap.chain = SWAP_CHAIN_ZCL;
        memset(swap.secret_hash, 0xAB, sizeof(swap.secret_hash));
        swap.amount = 100000;
        swap.locktime = 500000;
        snprintf(swap.my_address, sizeof(swap.my_address), "%s", "t1MyAddress");
        snprintf(swap.counter_address, sizeof(swap.counter_address), "%s",
                 "t1CounterAddress");
        swap.redeem_script_len = 97;
        snprintf(swap.p2sh_address, sizeof(swap.p2sh_address), "%s", "t3P2shAddress");
        ar_errors_clear(&e);
        bool ok = !db_swap_contract_validate(&swap, &e) &&
                  strstr(ar_errors_full(&e), "swap_id") != NULL;

        /* Fix the swap_id but zero the amount (must be positive). */
        snprintf(swap.swap_id, sizeof(swap.swap_id), "%s",
                 "deadbeef00112233445566778899aabbccddeeff0011223344556677889900");
        swap.amount = 0;
        ar_errors_clear(&e);
        ok = ok && !db_swap_contract_validate(&swap, &e) &&
             strstr(ar_errors_full(&e), "amount") != NULL;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Zmsg model requires a precomputed msg_id and rejects an empty body... ");
    {
        struct zmsg_message msg;
        struct ar_errors e;

        memset(&msg, 0, sizeof(msg));
        snprintf(msg.sender, sizeof(msg.sender), "%s", "alice");
        snprintf(msg.recipient, sizeof(msg.recipient), "%s", "bob");
        snprintf(msg.body, sizeof(msg.body), "%s", "hello");
        msg.direction = ZMSG_OUTBOUND;
        msg.channel = ZMSG_CHANNEL_P2P;
        msg.timestamp = 1700000000;
        ar_errors_clear(&e);
        /* msg_id is all-zero: must fail with a msg_id complaint. */
        bool ok = !db_zmsg_validate(&msg, &e) &&
                  strstr(ar_errors_full(&e), "msg_id") != NULL;

        memset(msg.msg_id, 0x42, sizeof(msg.msg_id));
        ar_errors_clear(&e);
        ok = ok && db_zmsg_validate(&msg, &e) && !ar_errors_any(&e);

        /* validates_presence_of does a byte-exact all-zero check, not a
         * string-emptiness check — zero the whole buffer, not just [0]. */
        memset(msg.body, 0, sizeof(msg.body));
        ar_errors_clear(&e);
        ok = ok && !db_zmsg_validate(&msg, &e) &&
             strstr(ar_errors_full(&e), "body") != NULL;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("hodl_wave_age_seconds is monotone and clamps at zero... ");
    {
        /* Pre-Buttercup UTXO (height 100) at a pre-Buttercup tip: age grows
         * purely from the 150s pre-Buttercup spacing. */
        int64_t age_pre = hodl_wave_age_seconds(100, 600000);
        bool ok = (age_pre == (int64_t)(707000 - 100) * 150);

        /* Pre-Buttercup UTXO observed from a post-Buttercup tip: adds the
         * 75s post-Buttercup segment on top of the fixed pre-Buttercup run. */
        int64_t age_pre_post_tip = hodl_wave_age_seconds(100, 800000);
        ok = ok && (age_pre_post_tip ==
                    (int64_t)(707000 - 100) * 150 + (int64_t)(800000 - 707000) * 75);

        /* Post-Buttercup UTXO: pure 75s spacing from mint height to tip. */
        int64_t age_post = hodl_wave_age_seconds(800000, 900000);
        ok = ok && (age_post == (int64_t)(900000 - 800000) * 75);

        /* A UTXO minted at (or after) the tip never reports negative age. */
        int64_t age_future = hodl_wave_age_seconds(900000, 800000);
        ok = ok && (age_future == 0);

        if (ok) printf("OK\n");
        else { printf("FAIL (pre=%lld pre_post=%lld post=%lld future=%lld)\n",
                       (long long)age_pre, (long long)age_pre_post_tip,
                       (long long)age_post, (long long)age_future);
               failures++; }
    }

    printf("hodl_wave_older_than_1y_percent computes a ratio and guards zero total... ");
    {
        struct hodl_wave_snapshot h;
        memset(&h, 0, sizeof(h));
        h.total_value = 0;
        h.older_than_1y_value = 0;
        bool ok = (hodl_wave_older_than_1y_percent(&h) == 0.0);
        ok = ok && (hodl_wave_older_than_1y_percent(NULL) == 0.0);

        h.total_value = 400;
        h.older_than_1y_value = 100;
        double pct = hodl_wave_older_than_1y_percent(&h);
        ok = ok && (pct > 24.999 && pct < 25.001);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Contact model validates and orders recent contacts... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "models_app", "contacts");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);
        if (ok) {
            struct db_contact bad, a, b, out[2];
            struct ar_errors e;
            memset(&bad, 0, sizeof(bad));
            ar_errors_clear(&e);
            db_contact_validate(&bad, &e);
            ok = ar_errors_any(&e);

            memset(&a, 0, sizeof(a));
            memset(&b, 0, sizeof(b));
            snprintf(a.address, sizeof(a.address), "%s", "t1Alice");
            snprintf(a.name, sizeof(a.name), "%s", "Alice");
            a.last_used = 10;
            snprintf(b.address, sizeof(b.address), "%s", "t1Bob");
            snprintf(b.name, sizeof(b.name), "%s", "Bob");
            b.last_used = 20;

            ok = ok && db_contact_save(&ndb, &a);
            ok = ok && db_contact_save(&ndb, &b);
            if (ok && db_contact_recent(&ndb, out, 2) != 2) {
                ok = false;
            }
            if (ok && strcmp(out[0].name, "Bob") != 0) {
                ok = false;
            }
            if (ok && strcmp(out[1].name, "Alice") != 0) {
                ok = false;
            }
            node_db_close(&ndb);
        }
        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Contact model trims whitespace before save... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "models_app", "contact_trim");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);
        if (ok) {
            struct db_contact c;
            struct db_contact out[1];
            memset(&c, 0, sizeof(c));
            memset(out, 0, sizeof(out));
            snprintf(c.address, sizeof(c.address), "%s", "  t1TrimMe  ");
            snprintf(c.name, sizeof(c.name), "%s", "  Alice Trim  ");
            ok = db_contact_save(&ndb, &c);
            if (ok && strcmp(c.address, "t1TrimMe") != 0) {
                ok = false;
            }
            if (ok && strcmp(c.name, "Alice Trim") != 0) {
                ok = false;
            }
            if (ok && db_contact_recent(&ndb, out, 1) != 1) {
                ok = false;
            }
            if (ok && strcmp(out[0].address, "t1TrimMe") != 0) {
                ok = false;
            }
            if (ok && strcmp(out[0].name, "Alice Trim") != 0) {
                ok = false;
            }
            node_db_close(&ndb);
        }
        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Onion announcement model validates suffix and persists... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "models_app", "onion");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);
        if (ok) {
            struct db_onion_announcement bad, good;
            struct ar_errors e;
            memset(&bad, 0, sizeof(bad));
            snprintf(bad.onion_address, sizeof(bad.onion_address), "%s", "not-onion");
            ar_errors_clear(&e);
            db_onion_announcement_validate(&bad, &e);
            ok = ar_errors_any(&e);

            memset(&good, 0, sizeof(good));
            snprintf(good.onion_address, sizeof(good.onion_address),
                     "%s",
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion");
            snprintf(good.script_hex, sizeof(good.script_hex), "%s", "6a01");
            ok = ok && db_onion_announcement_save(&ndb, &good);
            ok = ok && db_onion_announcement_exists(&ndb, good.onion_address);
            node_db_close(&ndb);
        }
        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Onion announcement model normalizes and lists recent rows... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "models_app", "onion_recent");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);
        if (ok) {
            struct db_onion_announcement first, second, listed[2];

            memset(&first, 0, sizeof(first));
            memset(&second, 0, sizeof(second));
            memset(listed, 0, sizeof(listed));

            snprintf(first.onion_address, sizeof(first.onion_address),
                     "%s", "  BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.onion  ");
            snprintf(first.script_hex, sizeof(first.script_hex), "%s", "  6A01AA  ");
            first.announced_at = 10;
            ok = db_onion_announcement_save(&ndb, &first);
            if (ok && strcmp(first.onion_address,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion") != 0) {
                ok = false;
            }
            if (ok && strcmp(first.script_hex, "6a01aa") != 0) {
                ok = false;
            }

            snprintf(second.onion_address, sizeof(second.onion_address),
                     "%s", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion");
            snprintf(second.script_hex, sizeof(second.script_hex), "%s", "6a02");
            second.announced_at = 20;
            ok = ok && db_onion_announcement_save(&ndb, &second);
            if (ok && db_onion_announcement_recent(&ndb, listed, 2) != 2) {
                ok = false;
            }
            if (ok && strcmp(listed[0].onion_address,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion") != 0) {
                ok = false;
            }
            if (ok && strcmp(listed[1].onion_address,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion") != 0) {
                ok = false;
            }
            node_db_close(&ndb);
        }

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Store product/order models validate and persist... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "models_app", "store");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);
        if (ok) {
            struct db_store_product p;
            struct db_store_order o;
            struct ar_errors e;
            struct db_store_product got_product;
            struct db_store_product active_products[4];
            struct db_store_order_view order_view;
            struct db_store_order_summary order_summaries[4];
            struct db_store_pending_payment pending[4];

            memset(&p, 0, sizeof(p));
            ar_errors_clear(&e);
            db_store_product_validate(&p, &e);
            ok = ar_errors_any(&e);

            memset(&p, 0, sizeof(p));
            snprintf(p.name, sizeof(p.name), "%s", "Widget");
            snprintf(p.description, sizeof(p.description), "%s", "Premium widget");
            snprintf(p.token_id, sizeof(p.token_id), "%s", " widget ");
            p.price_zatoshi = 1000;
            p.tokens_per_purchase = 2;
            p.active = true;
            ok = ok && db_store_product_save(&ndb, &p);
            if (ok && strcmp(p.token_id, "WIDGET") != 0) {
                fprintf(stderr, "store: product token_id='%s'\n", p.token_id);
                ok = false;
            }

            memset(&got_product, 0, sizeof(got_product));
            memset(active_products, 0, sizeof(active_products));
            if (ok && !db_store_product_find_active(&ndb, 1, &got_product)) {
                fprintf(stderr, "store: find active product failed\n");
                ok = false;
            }
            if (ok && strcmp(got_product.token_id, "WIDGET") != 0) {
                fprintf(stderr, "store: got_product.token_id='%s'\n", got_product.token_id);
                ok = false;
            }
            if (ok && db_store_product_list_active(&ndb, active_products, 4) != 1) {
                fprintf(stderr, "store: active product count mismatch\n");
                ok = false;
            }

            memset(&o, 0, sizeof(o));
            o.product_id = 1;
            snprintf(o.customer_addr, sizeof(o.customer_addr), "%s", " t1Buyer ");
            snprintf(o.payment_addr, sizeof(o.payment_addr), "%s", " zs1paymentaddress ");
            o.amount_zatoshi = 1000;
            o.status = 0;
            ok = ok && db_store_order_save(&ndb, &o);
            ok = ok && (o.id > 0);
            if (ok && strcmp(o.customer_addr, "t1Buyer") != 0) {
                fprintf(stderr, "store: customer_addr='%s'\n", o.customer_addr);
                ok = false;
            }
            if (ok && strcmp(o.payment_addr, "zs1paymentaddress") != 0) {
                fprintf(stderr, "store: payment_addr='%s'\n", o.payment_addr);
                ok = false;
            }
            if (ok && !db_store_order_mark_paid(&ndb, o.id, 2)) {
                fprintf(stderr, "store: mark_paid failed\n");
                ok = false;
            }

            memset(&order_view, 0, sizeof(order_view));
            memset(order_summaries, 0, sizeof(order_summaries));
            memset(pending, 0, sizeof(pending));
            if (ok && !db_store_order_find_view(&ndb, o.id, &order_view)) {
                fprintf(stderr, "store: order view lookup failed\n");
                ok = false;
            }
            if (ok && strcmp(order_view.customer_addr, "t1Buyer") != 0) {
                fprintf(stderr, "store: order_view.customer_addr='%s'\n",
                        order_view.customer_addr);
                ok = false;
            }
            if (ok && db_store_order_list_recent(&ndb, order_summaries, 4) != 1) {
                fprintf(stderr, "store: order recent count mismatch\n");
                ok = false;
            }
            if (ok && db_store_order_list_pending_payments(&ndb, pending, 4, 0) != 0) {
                fprintf(stderr, "store: pending payment count mismatch\n");
                ok = false;
            }
            node_db_close(&ndb);
        }
        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("File service model normalizes defaults and orders recent rows... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "models_app", "file_services");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);
        if (ok) {
            struct db_file_service a, b, listed[2];

            memset(&a, 0, sizeof(a));
            memset(&b, 0, sizeof(b));
            memset(listed, 0, sizeof(listed));
            memset(a.ip, 0x11, sizeof(a.ip));
            a.port = 8080;
            a.p2p_port = 0;
            a.last_seen = 0;
            a.is_zcl23 = true;
            ok = db_file_service_save(&ndb, &a);
            ok = ok && (a.p2p_port == 8080);
            ok = ok && (a.last_seen > 0);

            memset(b.ip, 0x22, sizeof(b.ip));
            b.port = 8081;
            b.p2p_port = 9001;
            b.last_seen = a.last_seen + 5;
            b.is_zcl23 = false;
            ok = ok && db_file_service_save(&ndb, &b);
            ok = ok && (db_file_service_recent(&ndb, listed, 2) == 2);
            ok = ok && (listed[0].port == 8081);
            ok = ok && (listed[1].p2p_port == 8080);
            node_db_close(&ndb);
        }
        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Peer model normalizes defaults and orders recent rows... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "models_app", "peers");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);
        if (ok) {
            struct db_peer a, b, c, d, listed[2], fast[4];

            memset(&a, 0, sizeof(a));
            memset(&b, 0, sizeof(b));
            memset(&c, 0, sizeof(c));
            memset(&d, 0, sizeof(d));
            memset(listed, 0, sizeof(listed));
            memset(fast, 0, sizeof(fast));
            memset(a.ip, 0x31, sizeof(a.ip));
            a.port = 8333;
            a.services = 9;
            a.last_seen = 0;
            a.last_try = -9;
            a.attempts = -1;
            a.bandwidth_score = 40;
            a.is_zcl23 = true;
            ok = db_peer_save(&ndb, &a);
            ok = ok && (a.last_seen > 0);
            ok = ok && (a.last_try == 0);
            ok = ok && (a.attempts == 0);

            memset(b.ip, 0x32, sizeof(b.ip));
            memset(b.source, 0x44, sizeof(b.source));
            b.has_source = true;
            b.port = 8334;
            b.services = 1;
            b.last_seen = a.last_seen + 5;
            b.bandwidth_score = 100;
            ok = ok && db_peer_save(&ndb, &b);
            ok = ok && (db_peer_recent(&ndb, listed, 2) == 2);
            ok = ok && (listed[0].port == 8334);
            ok = ok && listed[0].has_source;
            ok = ok && (listed[1].port == 8333);

            memset(c.ip, 0x33, sizeof(c.ip));
            c.port = 53100;
            c.services = 1;
            c.last_seen = a.last_seen + 10;
            c.bandwidth_score = 255;
            c.is_zcl23 = true;
            ok = ok && db_peer_save(&ndb, &c);

            memset(d.ip, 0x34, sizeof(d.ip));
            d.port = 8033;
            d.services = 1;
            d.last_seen = a.last_seen + 11;
            d.bandwidth_score = 1;
            d.is_zcl23 = true;
            ok = ok && db_peer_save(&ndb, &d);
            ok = ok && (db_peer_fast_zcl23(&ndb, fast, 4) == 1);
            ok = ok && (fast[0].port == 8033);
            node_db_close(&ndb);
        }
        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Wallet label model sets, reads back, relabels, and lists cleanly... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "models_app", "wallet_label");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);
        if (ok) {
            struct db_wallet_label bad, a, b, out;
            struct ar_errors e;

            /* An address-less row fails validation. */
            memset(&bad, 0, sizeof(bad));
            ar_errors_clear(&e);
            db_wallet_label_validate(&bad, &e);
            ok = ar_errors_any(&e);

            /* Set a label. */
            memset(&a, 0, sizeof(a));
            snprintf(a.address, sizeof(a.address), "%s", "t1Alice");
            snprintf(a.label, sizeof(a.label), "%s", "friends");
            ok = ok && db_wallet_label_save(&ndb, &a);

            /* Read it back. */
            memset(&out, 0, sizeof(out));
            ok = ok && db_wallet_label_find(&ndb, "t1Alice", &out);
            if (ok && strcmp(out.label, "friends") != 0)
                ok = false;

            /* An unknown address has no row (found=false, not an error). */
            memset(&out, 0, sizeof(out));
            if (ok && db_wallet_label_find(&ndb, "t1Nobody", &out))
                ok = false;

            /* A second address under the same label. */
            memset(&b, 0, sizeof(b));
            snprintf(b.address, sizeof(b.address), "%s", "t1Bob");
            snprintf(b.label, sizeof(b.label), "%s", "friends");
            ok = ok && db_wallet_label_save(&ndb, &b);

            struct db_wallet_label members[4];
            memset(members, 0, sizeof(members));
            int n = db_wallet_label_list_by_label(&ndb, "friends", members, 4);
            if (ok && n != 2) ok = false;
            if (ok && strcmp(members[0].address, "t1Alice") != 0) ok = false;
            if (ok && strcmp(members[1].address, "t1Bob") != 0) ok = false;

            /* An unknown label returns zero rows, not an error. */
            struct db_wallet_label none[4];
            memset(none, 0, sizeof(none));
            if (ok &&
                db_wallet_label_list_by_label(&ndb, "nonexistent", none, 4) != 0)
                ok = false;

            /* listlabels: exactly one distinct label so far. */
            struct db_wallet_label labels[4];
            memset(labels, 0, sizeof(labels));
            int nl = db_wallet_label_list_distinct(&ndb, labels, 4);
            if (ok && (nl != 1 || strcmp(labels[0].label, "friends") != 0))
                ok = false;

            /* Re-label Alice: the address primary key overwrites in place,
             * it does not create a second row. */
            struct db_wallet_label relabel;
            memset(&relabel, 0, sizeof(relabel));
            snprintf(relabel.address, sizeof(relabel.address), "%s", "t1Alice");
            snprintf(relabel.label, sizeof(relabel.label), "%s", "family");
            ok = ok && db_wallet_label_save(&ndb, &relabel);

            memset(&out, 0, sizeof(out));
            ok = ok && db_wallet_label_find(&ndb, "t1Alice", &out);
            if (ok && strcmp(out.label, "family") != 0)
                ok = false;

            struct db_wallet_label friends_after[4];
            memset(friends_after, 0, sizeof(friends_after));
            if (ok && db_wallet_label_list_by_label(&ndb, "friends",
                                                    friends_after, 4) != 1)
                ok = false;
            if (ok && strcmp(friends_after[0].address, "t1Bob") != 0)
                ok = false;

            struct db_wallet_label labels2[4];
            memset(labels2, 0, sizeof(labels2));
            int nl2 = db_wallet_label_list_distinct(&ndb, labels2, 4);
            if (ok && nl2 != 2) ok = false;

            /* Clearing a label keeps the row but empties it. */
            struct db_wallet_label cleared;
            memset(&cleared, 0, sizeof(cleared));
            snprintf(cleared.address, sizeof(cleared.address), "%s", "t1Bob");
            ok = ok && db_wallet_label_save(&ndb, &cleared);
            memset(&out, 0, sizeof(out));
            ok = ok && db_wallet_label_find(&ndb, "t1Bob", &out);
            if (ok && out.label[0] != '\0')
                ok = false;

            node_db_close(&ndb);
        }
        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
