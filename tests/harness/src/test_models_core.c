/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Focused model validation and ActiveRecord core tests. */

#include "test/test_core.h"
#include "models/utxo.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"

int test_model_core(void)
{
    int failures = 0;

    printf("UTXO validates presence of txid... ");
    {
        struct db_utxo u;
        struct ar_errors e;
        memset(&u, 0, sizeof(u));
        u.vout = 0;
        u.value = 100;
        u.height = 1;
        u.script_type = 1;
        ar_errors_clear(&e);
        db_utxo_validate(&u, &e);
        if (ar_errors_any(&e)) printf("OK\n");
        else { printf("FAIL (accepted blank txid)\n"); failures++; }
    }

    printf("UTXO validates value <= MAX_MONEY... ");
    {
        struct db_utxo u;
        struct ar_errors e;
        memset(&u, 0, sizeof(u));
        memset(u.txid, 0xAA, 32);
        u.value = 2100000100000000LL;
        u.height = 1;
        u.script_type = 1;
        ar_errors_clear(&e);
        db_utxo_validate(&u, &e);
        if (ar_errors_any(&e)) printf("OK\n");
        else { printf("FAIL (accepted value > MAX_MONEY)\n"); failures++; }
    }

    printf("UTXO validates height >= 0... ");
    {
        struct db_utxo u;
        struct ar_errors e;
        memset(&u, 0, sizeof(u));
        memset(u.txid, 0xBB, 32);
        u.value = 100;
        u.height = -1;
        u.script_type = 1;
        ar_errors_clear(&e);
        db_utxo_validate(&u, &e);
        if (ar_errors_any(&e)) printf("OK\n");
        else { printf("FAIL (accepted negative height)\n"); failures++; }
    }

    printf("UTXO accepts valid record... ");
    {
        struct db_utxo u;
        struct ar_errors e;
        memset(&u, 0, sizeof(u));
        memset(u.txid, 0xCC, 32);
        u.vout = 0;
        u.value = 1000000;
        u.height = 500000;
        u.script_type = 1;
        ar_errors_clear(&e);
        db_utxo_validate(&u, &e);
        if (!ar_errors_any(&e)) printf("OK\n");
        else { printf("FAIL (%s)\n", ar_errors_full(&e)); failures++; }
    }

    printf("WalletTx validates presence of txid... ");
    {
        struct db_wallet_tx wtx;
        struct ar_errors e;
        memset(&wtx, 0, sizeof(wtx));
        wtx.time_received = 1000;
        ar_errors_clear(&e);
        db_wallet_tx_validate(&wtx, &e);
        if (ar_errors_any(&e)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("WalletTx accepts valid record... ");
    {
        struct db_wallet_tx wtx;
        struct ar_errors e;
        memset(&wtx, 0, sizeof(wtx));
        memset(wtx.txid, 0xDD, 32);
        wtx.time_received = 1700000000;
        ar_errors_clear(&e);
        db_wallet_tx_validate(&wtx, &e);
        if (!ar_errors_any(&e)) printf("OK\n");
        else { printf("FAIL (%s)\n", ar_errors_full(&e)); failures++; }
    }

    printf("WalletUTXO validates value > MAX_MONEY... ");
    {
        struct db_wallet_utxo wu;
        struct ar_errors e;
        memset(&wu, 0, sizeof(wu));
        memset(wu.txid, 0xEE, 32);
        wu.value = 2200000000000000LL;
        wu.script_len = 25;
        ar_errors_clear(&e);
        db_wallet_utxo_validate(&wu, &e);
        if (ar_errors_any(&e)) printf("OK\n");
        else { printf("FAIL (accepted overflow value)\n"); failures++; }
    }

    printf("WalletUTXO validates script_len <= 10000... ");
    {
        struct db_wallet_utxo wu;
        struct ar_errors e;
        memset(&wu, 0, sizeof(wu));
        memset(wu.txid, 0xFF, 32);
        wu.value = 1000;
        wu.script_len = 50000;
        ar_errors_clear(&e);
        db_wallet_utxo_validate(&wu, &e);
        if (ar_errors_any(&e)) printf("OK\n");
        else { printf("FAIL (accepted oversized script)\n"); failures++; }
    }

    printf("WalletScript validates non-empty script hash and payload... ");
    {
        struct db_wallet_script ws;
        struct ar_errors e;
        memset(&ws, 0, sizeof(ws));
        ar_errors_clear(&e);
        db_wallet_script_validate(&ws, &e);
        if (ar_errors_any(&e)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("AR callbacks: before_save can halt save... ");
    {
        struct ar_callbacks cbs;
        int dummy = 42;
        bool ok;
        ar_callbacks_init(&cbs);
        ok = (cbs.n_before_save == 0);
        ok = ok && ar_run_before_save(&cbs, &dummy);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("AR callbacks: max 4 registration enforced... ");
    {
        struct ar_callbacks cbs;
        bool ok;
        ar_callbacks_init(&cbs);
        ok = (cbs.n_before_save == 0);
        cbs.n_before_save = 4;
        ok = ok && !ar_register_before_save(&cbs, NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("validates_range rejects out-of-range... ");
    {
        struct { int height; } rec = { .height = -5 };
        struct ar_errors e;
        ar_errors_clear(&e);
        validates_range(&e, &rec, height, 0, 10000000);
        if (ar_errors_any(&e)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("validates_range accepts in-range... ");
    {
        struct { int height; } rec = { .height = 500 };
        struct ar_errors e;
        ar_errors_clear(&e);
        validates_range(&e, &rec, height, 0, 10000000);
        if (!ar_errors_any(&e)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("ar_errors accumulates multiple errors... ");
    {
        struct ar_errors e;
        char buf[512];
        bool ok;
        ar_errors_clear(&e);
        ar_errors_add(&e, "field1", "is blank");
        ar_errors_add(&e, "field2", "is too large");
        ar_errors_add(&e, "field3", "is negative");
        ok = (e.count == 3);
        ar_errors_full_messages(&e, buf, sizeof(buf));
        ok = ok && (strstr(buf, "field1") != NULL);
        ok = ok && (strstr(buf, "field2") != NULL);
        ok = ok && (strstr(buf, "field3") != NULL);
        if (ok) printf("OK (%s)\n", buf);
        else { printf("FAIL\n"); failures++; }
    }

    printf("ar_errors overflow capped at 8... ");
    {
        struct ar_errors e;
        ar_errors_clear(&e);
        for (int i = 0; i < 12; i++)
            ar_errors_add(&e, "x", "err");
        if (e.count == 8) printf("OK\n");
        else { printf("FAIL (count=%d)\n", e.count); failures++; }
    }

    return failures;
}
