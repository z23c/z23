/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for shared scan utility data structures (scan_util.h). */

#include "test/test_core.h"
#include "services/scan_util.h"
#include "util/safe_alloc.h"

int test_scan_util(void)
{
    int failures = 0;

    printf("scan_util: scan_addr_ht init and insert... ");
    {
        struct scan_addr_ht ht;
        scan_aht_init(&ht);
        uint8_t h1[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
        uint8_t h2[20] = {20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};
        scan_aht_insert(&ht, h1);
        scan_aht_insert(&ht, h2);
        bool ok = (ht.count == 2);
        ok = ok && scan_aht_has(&ht, h1);
        ok = ok && scan_aht_has(&ht, h2);
        uint8_t h3[20] = {0};
        ok = ok && !scan_aht_has(&ht, h3);
        scan_aht_free(&ht);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("scan_util: scan_addr_ht dedup... ");
    {
        struct scan_addr_ht ht;
        scan_aht_init(&ht);
        uint8_t h[20] = {42};
        scan_aht_insert(&ht, h);
        scan_aht_insert(&ht, h);
        scan_aht_insert(&ht, h);
        bool ok = (ht.count == 1);
        scan_aht_free(&ht);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("scan_util: scan_utxo_set add and find... ");
    {
        struct scan_utxo_set us;
        scan_uset_init(&us);
        struct scan_mem_utxo u1 = {0};
        u1.txid[0] = 0xAA;
        u1.vout = 0;
        u1.value = 100000000;
        scan_uset_add(&us, &u1);

        struct scan_mem_utxo u2 = {0};
        u2.txid[0] = 0xBB;
        u2.vout = 1;
        u2.value = 200000000;
        scan_uset_add(&us, &u2);

        bool ok = (us.count == 2);
        ok = ok && (scan_uset_find(&us, u1.txid, 0) == 0);
        ok = ok && (scan_uset_find(&us, u2.txid, 1) == 1);
        /* Not found */
        uint8_t bad[32] = {0xFF};
        ok = ok && (scan_uset_find(&us, bad, 0) == -1);
        scan_uset_free(&us);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("scan_util: scan_wtx_list add... ");
    {
        struct scan_wtx_list wl;
        scan_wl_init(&wl);
        struct scan_mem_wtx w = {0};
        w.height = 100;
        w.raw = zcl_malloc(4, "test_wtx_raw");
        w.raw_len = 4;
        memcpy(w.raw, "test", 4);
        scan_wl_add(&wl, &w);
        bool ok = (wl.count == 1 && wl.items[0].height == 100);
        scan_wl_free(&wl);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("scan_util: scan_extract_addr P2PKH... ");
    {
        uint8_t script[25] = {0x76, 0xa9, 0x14,
            1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
            0x88, 0xac};
        uint8_t h[20];
        bool ok = scan_extract_addr(script, 25, h);
        ok = ok && (h[0] == 1 && h[19] == 20);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("scan_util: scan_extract_addr P2SH... ");
    {
        uint8_t script[23] = {0xa9, 0x14,
            10,20,30,40,50,60,70,80,90,100,110,120,130,140,150,160,170,180,190,200,
            0x87};
        uint8_t h[20];
        bool ok = scan_extract_addr(script, 23, h);
        ok = ok && (h[0] == 10 && h[19] == 200);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("scan_util: scan_extract_addr rejects non-standard... ");
    {
        uint8_t script[10] = {0xAA, 0xBB};
        uint8_t h[20];
        bool ok = !scan_extract_addr(script, 10, h);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("scan_util: scan_utxo_set grow beyond initial cap... ");
    {
        struct scan_utxo_set us;
        scan_uset_init(&us);
        for (int i = 0; i < 5000; i++) {
            struct scan_mem_utxo u = {0};
            u.txid[0] = (uint8_t)(i & 0xFF);
            u.txid[1] = (uint8_t)((i >> 8) & 0xFF);
            u.vout = (uint32_t)i;
            u.value = i * 100;
            scan_uset_add(&us, &u);
        }
        bool ok = (us.count == 5000);
        /* Find a specific one */
        struct scan_mem_utxo probe = {0};
        probe.txid[0] = (uint8_t)(4999 & 0xFF);
        probe.txid[1] = (uint8_t)((4999 >> 8) & 0xFF);
        int idx = scan_uset_find(&us, probe.txid, 4999);
        ok = ok && (idx >= 0) && (us.items[idx].value == 4999 * 100);
        scan_uset_free(&us);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
