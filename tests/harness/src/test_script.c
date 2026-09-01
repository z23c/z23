/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "chain/pow.h"
#include "coins/compressor.h"
#include "script/standard.h"
#include "coins/coins.h"
#include "script/sigencoding.h"
#include "support/pagelocker.h"
#include "script/interpreter.h"
#include "script/sigcache.h"
#include "consensus/validation.h"
#include "validation/sigops.h"
#if defined(_WIN32)
#include "platform/os_proc.h"
#else
#include <sys/resource.h>
#endif
#include <sys/time.h>

/* Process RSS in KiB: Linux ru_maxrss is already KiB, while Darwin reports
 * ru_maxrss in bytes. Windows uses the current working set through the
 * platform authority. Keep the unit normalized so the same "<10 MiB growth"
 * assertion means the same thing on every platform. */
static long ts_rss_kb(void)
{
#if defined(_WIN32)
    struct os_proc_mem m;
    if (!os_proc_mem_read(&m) || m.rss_bytes < 0)
        return 0;
    return (long)(m.rss_bytes / 1024);
#else
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0)
        return 0;
#if defined(__APPLE__)
    return ru.ru_maxrss / 1024;
#else
    return ru.ru_maxrss;
#endif
#endif
}

int test_script(void)
{
    int failures = 0;

    printf("script opcodes... ");
    {
        if (strcmp(script_get_op_name(OP_DUP), "OP_DUP") == 0 &&
            strcmp(script_get_op_name(OP_CHECKSIG), "OP_CHECKSIG") == 0 &&
            strcmp(script_get_op_name(OP_HASH160), "OP_HASH160") == 0) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("script P2PKH... ");
    {
        struct script s;
        script_init(&s);
        script_push_op(&s, OP_DUP);
        script_push_op(&s, OP_HASH160);
        unsigned char hash[20];
        memset(hash, 0xab, 20);
        script_push_data(&s, hash, 20);
        script_push_op(&s, OP_EQUALVERIFY);
        script_push_op(&s, OP_CHECKSIG);
        if (script_is_p2pkh(&s) && s.size == 25)
            printf("OK (size=%zu)\n", s.size);
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("compress_amount roundtrip... ");
    {
        uint64_t values[] = {0, 1, 100000000, 50000000, 2100000000000000ULL};
        bool ok = true;
        for (int i = 0; i < 5; i++) {
            uint64_t c = compress_amount(values[i]);
            uint64_t d = decompress_amount(c);
            if (d != values[i]) { ok = false; break; }
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_compress P2PKH... ");
    {
        struct script s;
        script_init(&s);
        script_push_op(&s, OP_DUP);
        script_push_op(&s, OP_HASH160);
        unsigned char hash20[20];
        memset(hash20, 0xAB, 20);
        script_push_data(&s, hash20, 20);
        script_push_op(&s, OP_EQUALVERIFY);
        script_push_op(&s, OP_CHECKSIG);

        unsigned char out[33];
        size_t out_len = 0;
        if (script_compress(&s, out, &out_len) && out_len == 21 &&
            out[0] == 0x00 && memcmp(out + 1, hash20, 20) == 0) {
            struct script decoded;
            script_decompress(&decoded, 0x00, out + 1, 20);
            if (decoded.size == 25 && script_is_p2pkh(&decoded))
                printf("OK\n");
            else { printf("FAIL (decompress)\n"); failures++; }
        } else { printf("FAIL (compress)\n"); failures++; }
    }

    printf("block_index_get_ancestor... ");
    {
        struct block_index blocks[5];
        for (int i = 0; i < 5; i++) {
            block_index_init(&blocks[i]);
            blocks[i].nHeight = i;
            blocks[i].pprev = i > 0 ? &blocks[i - 1] : NULL;
        }
        for (int i = 0; i < 5; i++)
            block_index_build_skip(&blocks[i]);

        struct block_index *anc = block_index_get_ancestor(&blocks[4], 1);
        if (anc == &blocks[1])
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("script_solver P2PKH... ");
    {
        struct key_id kid;
        uint160_set_null(&kid.id);
        unsigned char kbytes[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
        memcpy(kid.id.data, kbytes, 20);
        struct script s;
        script_for_p2pkh(&s, &kid);
        enum txnouttype type;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        size_t num_solutions;
        if (script_solver(&s, &type, solutions, solution_sizes, &num_solutions) &&
            type == TX_PUBKEYHASH && num_solutions == 1 && solution_sizes[0] == 20 &&
            solutions[0][0] == 1 && solutions[0][19] == 20)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_solver P2SH... ");
    {
        struct script_id sid;
        unsigned char sbytes[20] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff,0,0,0,0,0,0,0,0,0,0,0,0,0,0x11};
        memcpy(sid.hash.data, sbytes, 20);
        struct script s;
        script_for_p2sh(&s, &sid);
        enum txnouttype type;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        size_t num_solutions;
        if (script_solver(&s, &type, solutions, solution_sizes, &num_solutions) &&
            type == TX_SCRIPTHASH && num_solutions == 1 && solution_sizes[0] == 20 &&
            solutions[0][0] == 0xaa && solutions[0][19] == 0x11)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("utxo_classify_script... ");
    {
        uint8_t addr_hash[20];
        bool has_addr = false;
        bool ok = true;

        struct key_id kid;
        unsigned char kbytes[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
        memcpy(kid.id.data, kbytes, 20);
        struct script p2pkh;
        script_for_p2pkh(&p2pkh, &kid);
        ok = ok && utxo_classify_script(p2pkh.data, p2pkh.size,
                                        addr_hash, &has_addr) == SCRIPT_P2PKH;
        ok = ok && has_addr && memcmp(addr_hash, kbytes, 20) == 0;

        struct script_id sid;
        unsigned char sbytes[20] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff,0,0,0,0,0,0,0,0,0,0,0,0,0,0x11};
        memcpy(sid.hash.data, sbytes, 20);
        struct script p2sh;
        script_for_p2sh(&p2sh, &sid);
        ok = ok && utxo_classify_script(p2sh.data, p2sh.size,
                                        addr_hash, &has_addr) == SCRIPT_P2SH;
        ok = ok && has_addr && memcmp(addr_hash, sbytes, 20) == 0;

        uint8_t op_return[] = { OP_RETURN, 1, 0x42 };
        ok = ok && utxo_classify_script(op_return, sizeof(op_return),
                                        addr_hash, &has_addr) == SCRIPT_OP_RETURN;
        ok = ok && !has_addr;

        uint8_t other[] = { OP_TRUE };
        ok = ok && utxo_classify_script(other, sizeof(other),
                                        addr_hash, &has_addr) == SCRIPT_OTHER;
        ok = ok && !has_addr;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_extract_destination P2PKH... ");
    {
        struct key_id kid;
        unsigned char kbytes[20] = {10,20,30,40,50,60,70,80,90,100,110,120,130,140,150,160,170,180,190,200};
        memcpy(kid.id.data, kbytes, 20);
        struct script s;
        script_for_p2pkh(&s, &kid);
        struct tx_destination dest;
        if (script_extract_destination(&s, &dest) && dest.type == DEST_KEY_ID &&
            memcmp(dest.id.key.id.data, kid.id.data, 20) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_for_destination roundtrip... ");
    {
        struct key_id kid;
        unsigned char kbytes[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
        memcpy(kid.id.data, kbytes, 20);
        struct tx_destination dest = { .type = DEST_KEY_ID };
        memcpy(dest.id.key.id.data, kid.id.data, 20);
        struct script s;
        script_for_destination(&s, &dest);
        struct tx_destination dest2;
        if (script_extract_destination(&s, &dest2) && dest2.type == DEST_KEY_ID &&
            memcmp(dest2.id.key.id.data, kid.id.data, 20) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("get_txn_output_type... ");
    {
        if (strcmp(get_txn_output_type(TX_PUBKEYHASH), "pubkeyhash") == 0 &&
            strcmp(get_txn_output_type(TX_SCRIPTHASH), "scripthash") == 0 &&
            strcmp(get_txn_output_type(TX_NULL_DATA), "nulldata") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_id_from_script... ");
    {
        struct script s;
        struct key_id kid;
        memset(&kid, 0, sizeof(kid));
        script_for_p2pkh(&s, &kid);
        struct script_id sid;
        script_id_from_script(&sid, &s);
        bool non_zero = false;
        for (int i = 0; i < 20; i++) {
            if (sid.hash.data[i] != 0) { non_zero = true; break; }
        }
        if (non_zero)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("coins init/alloc/spend... ");
    {
        struct coins c;
        coins_init(&c);
        coins_alloc(&c, 3);
        c.vout[0].value = 50 * COIN;
        c.vout[1].value = 25 * COIN;
        c.vout[2].value = 10 * COIN;
        c.is_coinbase = true;
        c.height = 100;
        if (coins_is_available(&c, 0) && coins_is_available(&c, 1) &&
            !coins_is_pruned(&c)) {
            coins_spend(&c, 1);
            if (!coins_is_available(&c, 1) && coins_is_available(&c, 0)) {
                coins_spend(&c, 0);
                coins_spend(&c, 2);
                if (coins_is_pruned(&c))
                    printf("OK\n");
                else { printf("FAIL (not pruned)\n"); failures++; }
            } else { printf("FAIL (spend)\n"); failures++; }
        } else { printf("FAIL (init)\n"); failures++; }
        coins_free(&c);
    }

    printf("coins_from_transaction... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 2);
        tx.vout[0].value = 100 * COIN;
        tx.vout[1].value = 50 * COIN;
        tx.version = 1;

        struct coins c;
        coins_init(&c);
        coins_from_transaction(&c, &tx, 500);
        if (c.height == 500 && c.version == 1 &&
            c.is_coinbase && c.num_vout == 2 &&
            c.vout[0].value == 100 * COIN)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        coins_free(&c);
        transaction_free(&tx);
    }

    printf("script_num roundtrip... ");
    {
        int64_t values[] = {0, 1, -1, 127, -128, 255, -255, 32767, -32768,
                            2147483647LL, -2147483647LL};
        bool ok = true;
        for (int i = 0; i < 11; i++) {
            struct script_num sn = script_num_from_int(values[i]);
            unsigned char buf[8];
            size_t len = script_num_serialize(&sn, buf, sizeof(buf));
            struct script_num sn2;
            if (!script_num_from_bytes(&sn2, buf, len, true, 8) ||
                sn2.value != values[i]) {
                ok = false; break;
            }
        }
        if (ok)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* script_num_serialize rejects short buffers instead of
     * silently truncating. Max output for any valid int64 magnitude is
     * SCRIPT_NUM_MAX_SIZE (8 bytes). */
    printf("script_num_serialize outsize bounds... ");
    {
        bool ok = true;

        /* Guard sentinels around a 1-byte buffer. INT64_MAX needs 8
         * bytes, so the call must return 0 and leave both sentinels
         * untouched. The previous implementation silently wrote byte 0
         * and reported len=1, producing malformed script. */
        unsigned char guard[3] = { 0xAA, 0xAA, 0xAA };
        unsigned char *buf = &guard[1];
        struct script_num huge = script_num_from_int(INT64_MAX);
        if (script_num_serialize(&huge, buf, 1) != 0) ok = false;
        if (guard[0] != 0xAA || guard[1] != 0xAA || guard[2] != 0xAA)
            ok = false;

        /* Value 128 needs 2 bytes (0x80 magnitude + 0x00 sign byte).
         * A 1-byte buffer must reject the request; a 2-byte buffer
         * must accept it with both bytes written. */
        struct script_num oneTwentyEight = script_num_from_int(128);
        unsigned char one[1] = { 0xDD };
        if (script_num_serialize(&oneTwentyEight, one, sizeof(one)) != 0) ok = false;
        if (one[0] != 0xDD) ok = false;

        unsigned char two[2];
        size_t len = script_num_serialize(&oneTwentyEight, two, sizeof(two));
        if (len != 2 || two[0] != 0x80 || two[1] != 0x00) ok = false;

        /* Eight bytes is sufficient for INT64_MAX — round-trip. */
        unsigned char eight[8];
        len = script_num_serialize(&huge, eight, sizeof(eight));
        if (len != 8) ok = false;
        struct script_num back;
        if (!script_num_from_bytes(&back, eight, len, true, sizeof(eight)) ||
            back.value != INT64_MAX)
            ok = false;

        /* INT64_MIN + 1 is the most negative representable magnitude
         * (INT64_MIN's absolute value overflows int64 negation). Eight
         * bytes still suffices because the top magnitude byte (0x7f)
         * leaves the sign bit free. */
        struct script_num deep = script_num_from_int(INT64_MIN + 1);
        unsigned char neg[8];
        len = script_num_serialize(&deep, neg, sizeof(neg));
        if (len != 8) ok = false;
        if (!script_num_from_bytes(&back, neg, len, true, sizeof(neg)) ||
            back.value != INT64_MIN + 1)
            ok = false;

        /* Value == 0 returns 0 without touching the buffer — the
         * "short buffer" case is distinguishable by inspecting
         * sn->value. */
        unsigned char zbuf[8];
        memset(zbuf, 0xCC, sizeof(zbuf));
        struct script_num zero = script_num_from_int(0);
        if (script_num_serialize(&zero, zbuf, sizeof(zbuf)) != 0) ok = false;
        for (size_t i = 0; i < sizeof(zbuf); i++)
            if (zbuf[i] != 0xCC) { ok = false; break; }

        if (ok)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_get_op... ");
    {
        struct script s;
        script_init(&s);
        script_push_op(&s, OP_DUP);
        unsigned char payload[] = {0xAA, 0xBB};
        script_push_data(&s, payload, 2);
        script_push_op(&s, OP_CHECKSIG);

        size_t pc = 0;
        enum opcodetype op;
        unsigned char data[520];
        size_t datalen;
        bool ok = true;
        ok &= script_get_op(&s, &pc, &op, data, &datalen);
        ok &= (op == OP_DUP && datalen == 0);
        ok &= script_get_op(&s, &pc, &op, data, &datalen);
        ok &= (datalen == 2 && data[0] == 0xAA && data[1] == 0xBB);
        ok &= script_get_op(&s, &pc, &op, data, &datalen);
        ok &= (op == OP_CHECKSIG);
        ok &= (pc == s.size);
        if (ok)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_is_push_only... ");
    {
        struct script s;
        script_init(&s);
        unsigned char data[] = {1, 2, 3};
        script_push_data(&s, data, 3);
        if (script_is_push_only(&s)) {
            script_push_op(&s, OP_CHECKSIG);
            if (!script_is_push_only(&s))
                printf("OK\n");
            else { printf("FAIL (non-push passed)\n"); failures++; }
        } else { printf("FAIL (push-only failed)\n"); failures++; }
    }

    /* The OP_PUSHDATA4 advance is computed at 32 bits and wraps. That wrap
     * is load-bearing: it is what gives the last four lengths below their
     * verdict, and this rule feeds the P2SH push-only check on scriptSig
     * bytes supplied by whoever sent the transaction. So this pins the
     * VERDICT for each length across the wrap boundary, not merely that the
     * call returns — widening the addition would still return, and would
     * silently turn all four false answers into true.
     *
     * 0xFFFFFFFB is the sole length whose advance is zero. It is the one
     * input the cursor cannot answer at all, and it must answer false. On a
     * cursor that does not refuse it, this test does not fail — it hangs. */
    printf("script_is_push_only: pushdata4 verdicts across the wrap... ");
    {
        static const struct { uint32_t len; bool want; } cases[] = {
            { 1000u,       true  },   /* ordinary oversize push        */
            { 0xfffffff9u, true  },   /* advance 0xFFFFFFFE, past end  */
            { 0xfffffffau, true  },   /* advance 0xFFFFFFFF, past end  */
            { 0xfffffffbu, false },   /* advance 0 — refused outright  */
            { 0xfffffffcu, false },   /* advance 1, lands on 0xFC      */
            { 0xfffffffdu, false },   /* advance 2, lands on 0xFD      */
            { 0xfffffffeu, false },   /* advance 3, lands on 0xFE      */
            { 0xffffffffu, false },   /* advance 4, lands on 0xFF      */
        };
        bool ok = true;
        for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
            unsigned char raw[5] = {
                OP_PUSHDATA4,
                (unsigned char)(cases[k].len         & 0xff),
                (unsigned char)((cases[k].len >>  8) & 0xff),
                (unsigned char)((cases[k].len >> 16) & 0xff),
                (unsigned char)((cases[k].len >> 24) & 0xff),
            };
            struct script s;
            script_init(&s);
            script_set(&s, raw, sizeof(raw));
            if (script_is_push_only(&s) != cases[k].want) {
                printf("FAIL (len=0x%08x want %s) ", cases[k].len,
                       cases[k].want ? "true" : "false");
                ok = false;
            }
        }
        if (ok)
            printf("OK\n");
        else { printf("\n"); failures++; }
    }

    printf("sigencoding valid DER... ");
    {
        unsigned char sig[70];
        sig[0] = 0x30; sig[1] = 68;
        sig[2] = 0x02; sig[3] = 32;
        memset(&sig[4], 0x01, 32);
        sig[36] = 0x02; sig[37] = 32;
        memset(&sig[38], 0x01, 32);
        ScriptError err = SCRIPT_ERR_OK;
        bool ok = check_data_signature_encoding(sig, 70, 0, &err);
        if (ok && err == SCRIPT_ERR_OK)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("sigencoding invalid DER... ");
    {
        unsigned char sig[] = {0x30, 0x01, 0x00};
        ScriptError err = SCRIPT_ERR_OK;
        bool ok = check_data_signature_encoding(sig, 3, 0, &err);
        if (!ok && err == SCRIPT_ERR_SIG_DER)
            printf("OK\n");
        else { printf("FAIL (ok=%d, err=%d)\n", ok, err); failures++; }
    }

    printf("sigencoding empty sig... ");
    {
        ScriptError err = SCRIPT_ERR_OK;
        if (check_data_signature_encoding(NULL, 0, 0, &err) &&
            check_transaction_signature_encoding(NULL, 0, 0, &err))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* strict-DER parity with canonical Zcash Bitcoin encoding.
     *
     * The is_valid_signature_encoding routine is BIP66 consensus-critical:
     * any divergence from the upstream rules forks the network. These
     * vectors pin the boundary behavior so a future refactor can't
     * silently drift off the canonical interpretation.
     *
     * Each vector is a *data signature* (no trailing sighash byte). The
     * DER bytes run from sig[0] to sig[len-1]. Expectations are written
     * against check_data_signature_encoding, which calls
     * is_valid_signature_encoding directly. */
    printf("sigencoding strict-DER parity vectors... ");
    {
        struct vec { const unsigned char *bytes; size_t len; bool valid;
                     const char *label; };

        /* Minimum-size valid signature: 8-byte DER, 1-byte R=1, 1-byte
         * S=1. Anything shorter must be rejected. */
        static const unsigned char v_min_valid[] = {
            0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01
        };
        static const unsigned char v_too_short[] = {
            0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01
        };
        static const unsigned char v_bad_compound[] = {
            0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01
        };
        static const unsigned char v_wrong_total_len[] = {
            0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01
        };
        static const unsigned char v_r_not_int[] = {
            0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01
        };
        static const unsigned char v_r_negative[] = {
            0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01
        };
        /* lenR=2, R=[00, 05]: null-padded but next byte is not negative,
         * so the padding is excessive — must reject. */
        static const unsigned char v_r_null_pad_bad[] = {
            0x30, 0x07, 0x02, 0x02, 0x00, 0x05, 0x02, 0x01, 0x01
        };
        /* Same shape but next byte has its high bit set — padding is
         * mandatory here, must accept. */
        static const unsigned char v_r_null_pad_ok[] = {
            0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01
        };
        /* lenR=0 — always rejected. */
        static const unsigned char v_r_zero_len[] = {
            0x30, 0x06, 0x02, 0x00, 0x02, 0x02, 0x01, 0x01
        };
        /* lenR larger than fits in signature: 3 > len - 7 = 1. */
        static const unsigned char v_r_too_long[] = {
            0x30, 0x06, 0x02, 0x03, 0x01, 0x01, 0x02, 0x01
        };
        /* lenS=0 — always rejected. */
        static const unsigned char v_s_zero_len[] = {
            0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x00, 0x01
        };
        /* S negative. */
        static const unsigned char v_s_negative[] = {
            0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x80
        };
        /* S null-padded but not needed — reject. */
        static const unsigned char v_s_null_pad_bad[] = {
            0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x05
        };
        /* S null-padded, next byte negative — accept. */
        static const unsigned char v_s_null_pad_ok[] = {
            0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80
        };
        /* 72-byte DER at the upper boundary. Structure:
         *   [30] [70] [02] [33] [33-byte R with leading 0x00 null-pad]
         *              [02] [33] [33-byte S with leading 0x00 null-pad]
         * The null-pad is mandatory because the first real byte has its
         * high bit set, so lenR = lenS = 33 is the canonical form. */
        static unsigned char v_max_valid[72];
        v_max_valid[0] = 0x30; v_max_valid[1] = 70;
        v_max_valid[2] = 0x02; v_max_valid[3] = 33;
        v_max_valid[4] = 0x00;
        for (int k = 0; k < 32; k++) v_max_valid[5 + k] = 0x80 + (k & 0x7f);
        v_max_valid[37] = 0x02; v_max_valid[38] = 33;
        v_max_valid[39] = 0x00;
        for (int k = 0; k < 32; k++) v_max_valid[40 + k] = 0x80 + (k & 0x7f);
        /* 73-byte signature — exceeds the max bound. Content is the
         * valid 72-byte form with a trailing junk byte. */
        static unsigned char v_too_long[73];
        memcpy(v_too_long, v_max_valid, 72);
        v_too_long[72] = 0xff;
        /* Not a real total-length anymore; adjust so the check that
         * triggers is len > 72 (the size bound) rather than something
         * structural. */

        struct vec vectors[] = {
            {v_min_valid,        sizeof(v_min_valid),      true,  "min valid"},
            {v_too_short,        sizeof(v_too_short),      false, "too short (<8)"},
            {v_bad_compound,     sizeof(v_bad_compound),   false, "bad compound type"},
            {v_wrong_total_len,  sizeof(v_wrong_total_len),false, "wrong total-length"},
            {v_r_not_int,        sizeof(v_r_not_int),      false, "R not int"},
            {v_r_negative,       sizeof(v_r_negative),     false, "R negative"},
            {v_r_null_pad_bad,   sizeof(v_r_null_pad_bad), false, "R null-pad excessive"},
            {v_r_null_pad_ok,    sizeof(v_r_null_pad_ok),  true,  "R null-pad mandatory"},
            {v_r_zero_len,       sizeof(v_r_zero_len),     false, "R zero length"},
            {v_r_too_long,       sizeof(v_r_too_long),     false, "R too long"},
            {v_s_zero_len,       sizeof(v_s_zero_len),     false, "S zero length"},
            {v_s_negative,       sizeof(v_s_negative),     false, "S negative"},
            {v_s_null_pad_bad,   sizeof(v_s_null_pad_bad), false, "S null-pad excessive"},
            {v_s_null_pad_ok,    sizeof(v_s_null_pad_ok),  true,  "S null-pad mandatory"},
            {v_max_valid,        sizeof(v_max_valid),      true,  "max valid (72 bytes)"},
            {v_too_long,         sizeof(v_too_long),       false, "too long (>72)"},
        };

        bool ok = true;
        for (size_t vi = 0; vi < sizeof(vectors) / sizeof(vectors[0]); vi++) {
            struct vec *v = &vectors[vi];
            ScriptError err = SCRIPT_ERR_OK;
            bool got = check_data_signature_encoding(v->bytes, v->len, 0, &err);
            if (got != v->valid) {
                printf("\n  [%s] expected=%d got=%d err=%d",
                       v->label, v->valid, got, err);
                ok = false;
            }
        }
        if (ok) printf("OK\n");
        else { printf("\nFAIL\n"); failures++; }
    }

    printf("check_pubkey_encoding... ");
    {
        unsigned char compressed[33] = {0x02};
        unsigned char uncompressed[65] = {0x04};
        unsigned char bad[10] = {0x05};
        ScriptError err;
        if (check_pubkey_encoding(compressed, 33, SCRIPT_VERIFY_STRICTENC, &err) &&
            check_pubkey_encoding(uncompressed, 65, SCRIPT_VERIFY_STRICTENC, &err) &&
            !check_pubkey_encoding(bad, 10, SCRIPT_VERIFY_STRICTENC, &err))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("eval_script OP_TRUE... ");
    {
        struct script s;
        script_init(&s);
        script_push_op(&s, OP_TRUE);
        struct script_stack stk __attribute__((cleanup(stack_free))) = {0};
        stack_init(&stk);
        ScriptError err;
        bool ok = eval_script(&stk, &s, 0, NULL, 0, &err);
        if (ok && stk.count == 1 && cast_to_bool(stack_top(&stk, -1)))
            printf("OK\n");
        else { printf("FAIL (ok=%d, count=%zu)\n", ok, stk.count); failures++; }
    }

    printf("eval_script OP_ADD... ");
    {
        struct script s;
        script_init(&s);
        script_push_op(&s, OP_2);
        script_push_op(&s, OP_3);
        script_push_op(&s, OP_ADD);
        struct script_stack stk __attribute__((cleanup(stack_free))) = {0};
        stack_init(&stk);
        ScriptError err;
        bool ok = eval_script(&stk, &s, 0, NULL, 0, &err);
        if (ok && stk.count == 1) {
            struct script_num sn = {0};
            script_num_from_bytes(&sn, stack_top(&stk, -1)->data,
                                  stack_top(&stk, -1)->size, false, 4);
            if (sn.value == 5)
                printf("OK\n");
            else { printf("FAIL (value=%" PRId64 ")\n", sn.value); failures++; }
        } else { printf("FAIL\n"); failures++; }
    }

    printf("eval_script OP_EQUAL... ");
    {
        struct script s;
        script_init(&s);
        script_push_op(&s, OP_5);
        script_push_op(&s, OP_5);
        script_push_op(&s, OP_EQUAL);
        struct script_stack stk __attribute__((cleanup(stack_free))) = {0};
        stack_init(&stk);
        ScriptError err;
        bool ok = eval_script(&stk, &s, 0, NULL, 0, &err);
        if (ok && stk.count == 1 && cast_to_bool(stack_top(&stk, -1)))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("eval_script OP_DUP OP_HASH160... ");
    {
        struct script s;
        script_init(&s);
        unsigned char data[] = {0x01, 0x02, 0x03};
        script_push_data(&s, data, 3);
        script_push_op(&s, OP_DUP);
        script_push_op(&s, OP_HASH160);
        struct script_stack stk __attribute__((cleanup(stack_free))) = {0};
        stack_init(&stk);
        ScriptError err;
        bool ok = eval_script(&stk, &s, 0, NULL, 0, &err);
        if (ok && stk.count == 2 && stack_top(&stk, -1)->size == 20)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("verify_script P2PKH (no checker)... ");
    {
        struct key_id kid;
        memset(&kid, 0xAB, sizeof(kid));
        struct script spk;
        script_for_p2pkh(&spk, &kid);
        struct script ss;
        script_init(&ss);
        ScriptError err;
        bool ok = verify_script(&ss, &spk, 0, NULL, 0, &err);
        if (!ok)
            printf("OK (correctly fails without sig)\n");
        else { printf("FAIL (should have failed)\n"); failures++; }
    }

    printf("eval_script OP_IF/OP_ELSE/OP_ENDIF... ");
    {
        struct script s;
        script_init(&s);
        script_push_op(&s, OP_1);
        script_push_op(&s, OP_IF);
        script_push_op(&s, OP_2);
        script_push_op(&s, OP_ELSE);
        script_push_op(&s, OP_3);
        script_push_op(&s, OP_ENDIF);
        struct script_stack stk __attribute__((cleanup(stack_free))) = {0};
        stack_init(&stk);
        ScriptError err;
        bool ok = eval_script(&stk, &s, 0, NULL, 0, &err);
        if (ok && stk.count == 1) {
            struct script_num sn = {0};
            script_num_from_bytes(&sn, stack_top(&stk, -1)->data,
                                  stack_top(&stk, -1)->size, false, 4);
            if (sn.value == 2)
                printf("OK\n");
            else { printf("FAIL (value=%" PRId64 ")\n", sn.value); failures++; }
        } else { printf("FAIL\n"); failures++; }
    }

    printf("validation_state... ");
    {
        struct validation_state vs;
        validation_state_init(&vs);
        if (validation_state_is_valid(&vs)) {
            validation_state_dos(&vs, 10, false, REJECT_INVALID,
                                 "bad-txns", false, NULL);
            int dos = 0;
            if (validation_state_is_invalid(&vs) &&
                validation_state_get_dos(&vs, &dos) && dos == 10 &&
                strcmp(vs.reject_reason, "bad-txns") == 0)
                printf("OK\n");
            else { printf("FAIL\n"); failures++; }
        } else { printf("FAIL (init)\n"); failures++; }
    }

    printf("sigcache set/get/erase... ");
    {
        struct sig_cache cache;
        sig_cache_init(&cache);
        struct uint256 hash;
        memset(hash.data, 0x42, 32);
        unsigned char sig[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
        unsigned char pk[] = {0x02, 0x01};
        struct uint256 entry;
        sig_cache_compute_entry(&cache, &entry, &hash, sig, 8, pk, 2);
        if (!sig_cache_get(&cache, &entry)) {
            sig_cache_set(&cache, &entry);
            if (sig_cache_get(&cache, &entry)) {
                sig_cache_erase(&cache, &entry);
                if (!sig_cache_get(&cache, &entry))
                    printf("OK\n");
                else { printf("FAIL (erase)\n"); failures++; }
            } else { printf("FAIL (get after set)\n"); failures++; }
        } else { printf("FAIL (false positive)\n"); failures++; }
        sig_cache_destroy(&cache);
    }

    printf("pagelocker lock/unlock... ");
    {
        struct locked_page_manager m;
        locked_page_manager_init(&m);
        unsigned char buf[64];
        locked_page_manager_lock_range(&m, buf, sizeof(buf));
        int count = locked_page_manager_get_count(&m);
        locked_page_manager_unlock_range(&m, buf, sizeof(buf));
        int count2 = locked_page_manager_get_count(&m);
        if (count >= 1 && count2 == 0)
            printf("OK (locked=%d, unlocked=%d)\n", count, count2);
        else { printf("FAIL (locked=%d, unlocked=%d)\n", count, count2); failures++; }
        locked_page_manager_destroy(&m);
    }

    printf("lock_object/unlock_object... ");
    {
        unsigned char secret[32];
        memset(secret, 0xAA, 32);
        lock_object(secret, sizeof(secret));
        unlock_object(secret, sizeof(secret));
        bool zeroed = true;
        for (int i = 0; i < 32; i++) {
            if (secret[i] != 0) { zeroed = false; break; }
        }
        if (zeroed)
            printf("OK (memory cleansed)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_get_sig_op_count... ");
    {
        struct script s;
        s.data[0] = OP_CHECKSIG;
        s.data[1] = OP_CHECKSIG;
        s.data[2] = OP_CHECKMULTISIG;
        s.size = 3;
        uint32_t n = script_get_sig_op_count(&s, 0, false);
        if (n == 22)
            printf("OK\n");
        else { printf("FAIL (%u)\n", n); failures++; }
    }

    printf("script_get_sig_op_count accurate... ");
    {
        struct script s;
        s.data[0] = OP_2;
        s.data[1] = OP_CHECKMULTISIG;
        s.size = 2;
        uint32_t n = script_get_sig_op_count(&s, 0, true);
        if (n == 2)
            printf("OK\n");
        else { printf("FAIL (%u)\n", n); failures++; }
    }

    printf("get_legacy_sig_op_count... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.version = 1;
        memset(tx.vin[0].prevout.hash.data, 0x11, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].script_sig.size = 0;
        tx.vout[0].value = COIN;
        tx.vout[0].script_pub_key.data[0] = OP_CHECKSIG;
        tx.vout[0].script_pub_key.size = 1;
        uint64_t ops = get_legacy_sig_op_count(&tx, 0);
        if (ops == 1)
            printf("OK\n");
        else { printf("FAIL (%" PRIu64 ")\n", ops); failures++; }
        transaction_free(&tx);
    }

    printf("script_is_pay_to_script_hash... ");
    {
        struct script s;
        s.data[0] = OP_HASH160;
        s.data[1] = 0x14;
        memset(s.data + 2, 0xAA, 20);
        s.data[22] = OP_EQUAL;
        s.size = 23;
        if (script_is_pay_to_script_hash(&s))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * script_solver: P2SH detection
     * ================================================================ */
    printf("script_solver: P2SH... ");
    {
        struct script s;
        s.data[0] = OP_HASH160;
        s.data[1] = 20;
        memset(s.data + 2, 0xBB, 20);
        s.data[22] = OP_EQUAL;
        s.size = 23;

        enum txnouttype type;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        size_t num_solutions;
        bool ok = script_solver(&s, &type, solutions, solution_sizes, &num_solutions);
        ok = ok && (type == TX_SCRIPTHASH) && (num_solutions == 1) && (solution_sizes[0] == 20);
        ok = ok && (solutions[0][0] == 0xBB);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_solver: OP_RETURN null data... ");
    {
        struct script s;
        s.data[0] = OP_RETURN;
        s.data[1] = 4; /* push 4 bytes */
        s.data[2] = 0xDE;
        s.data[3] = 0xAD;
        s.data[4] = 0xBE;
        s.data[5] = 0xEF;
        s.size = 6;

        enum txnouttype type;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        size_t num_solutions;
        bool ok = script_solver(&s, &type, solutions, solution_sizes, &num_solutions);
        ok = ok && (type == TX_NULL_DATA);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_solver: P2PK compressed... ");
    {
        struct script s;
        s.data[0] = 33; /* push 33 bytes */
        s.data[1] = 0x02; /* compressed pubkey prefix */
        memset(s.data + 2, 0xCC, 32);
        s.data[34] = OP_CHECKSIG;
        s.size = 35;

        enum txnouttype type;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        size_t num_solutions;
        bool ok = script_solver(&s, &type, solutions, solution_sizes, &num_solutions);
        ok = ok && (type == TX_PUBKEY) && (num_solutions == 1) && (solution_sizes[0] == 33);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_solver: nonstandard... ");
    {
        struct script s;
        s.data[0] = OP_NOP;
        s.data[1] = OP_NOP;
        s.size = 2;

        enum txnouttype type;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        size_t num_solutions;
        bool ok = !script_solver(&s, &type, solutions, solution_sizes, &num_solutions);
        ok = ok && (type == TX_NONSTANDARD);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * get_txn_output_type: name strings
     * ================================================================ */
    printf("get_txn_output_type: all types... ");
    {
        bool ok = (strcmp(get_txn_output_type(TX_NONSTANDARD), "nonstandard") == 0) &&
                  (strcmp(get_txn_output_type(TX_PUBKEY), "pubkey") == 0) &&
                  (strcmp(get_txn_output_type(TX_PUBKEYHASH), "pubkeyhash") == 0) &&
                  (strcmp(get_txn_output_type(TX_SCRIPTHASH), "scripthash") == 0) &&
                  (strcmp(get_txn_output_type(TX_MULTISIG), "multisig") == 0) &&
                  (strcmp(get_txn_output_type(TX_NULL_DATA), "nulldata") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * script_for_p2sh: build + roundtrip via solver
     * ================================================================ */
    printf("script_for_p2sh: builds valid P2SH... ");
    {
        struct script_id sid;
        memset(sid.hash.data, 0xDD, 20);
        struct script s;
        script_for_p2sh(&s, &sid);

        bool ok = (s.size == 23) && (s.data[0] == OP_HASH160) && (s.data[22] == OP_EQUAL);

        enum txnouttype type;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        size_t num_solutions;
        ok = ok && script_solver(&s, &type, solutions, solution_sizes, &num_solutions);
        ok = ok && (type == TX_SCRIPTHASH);
        ok = ok && (memcmp(solutions[0], sid.hash.data, 20) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * script_for_p2pkh: build + roundtrip via solver
     * ================================================================ */
    printf("script_for_p2pkh: builds valid P2PKH... ");
    {
        struct key_id kid;
        memset(kid.id.data, 0xEE, 20);
        struct script s;
        script_for_p2pkh(&s, &kid);

        bool ok = (s.size == 25) && (s.data[0] == OP_DUP) && (s.data[24] == OP_CHECKSIG);

        enum txnouttype type;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        size_t num_solutions;
        ok = ok && script_solver(&s, &type, solutions, solution_sizes, &num_solutions);
        ok = ok && (type == TX_PUBKEYHASH);
        ok = ok && (memcmp(solutions[0], kid.id.data, 20) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * script_extract_destination: P2PKH
     * ================================================================ */
    printf("script_extract_destination: P2PKH... ");
    {
        struct key_id kid;
        memset(kid.id.data, 0x42, 20);
        struct script s;
        script_for_p2pkh(&s, &kid);

        struct tx_destination dest;
        memset(&dest, 0, sizeof(dest));
        bool ok = script_extract_destination(&s, &dest);
        ok = ok && (dest.type == DEST_KEY_ID);
        ok = ok && (memcmp(dest.id.key.id.data, kid.id.data, 20) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_extract_destination: P2SH... ");
    {
        struct script_id sid;
        memset(sid.hash.data, 0x55, 20);
        struct script s;
        script_for_p2sh(&s, &sid);

        struct tx_destination dest;
        memset(&dest, 0, sizeof(dest));
        bool ok = script_extract_destination(&s, &dest);
        ok = ok && (dest.type == DEST_SCRIPT_ID);
        ok = ok && (memcmp(dest.id.script.hash.data, sid.hash.data, 20) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_extract_destination: nonstandard fails... ");
    {
        struct script s;
        s.data[0] = OP_NOP;
        s.size = 1;

        struct tx_destination dest;
        memset(&dest, 0, sizeof(dest));
        bool ok = !script_extract_destination(&s, &dest);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * script_for_destination: roundtrip via extract
     * ================================================================ */
    printf("script_for_destination: P2PKH roundtrip... ");
    {
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        memset(dest.id.key.id.data, 0x77, 20);
        struct script s;
        script_for_destination(&s, &dest);

        struct tx_destination dest2;
        memset(&dest2, 0, sizeof(dest2));
        bool ok = script_extract_destination(&s, &dest2);
        ok = ok && (dest2.type == DEST_KEY_ID);
        ok = ok && (memcmp(dest2.id.key.id.data, dest.id.key.id.data, 20) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_for_destination: P2SH roundtrip... ");
    {
        struct tx_destination dest;
        dest.type = DEST_SCRIPT_ID;
        memset(dest.id.script.hash.data, 0x88, 20);
        struct script s;
        script_for_destination(&s, &dest);

        struct tx_destination dest2;
        memset(&dest2, 0, sizeof(dest2));
        bool ok = script_extract_destination(&s, &dest2);
        ok = ok && (dest2.type == DEST_SCRIPT_ID);
        ok = ok && (memcmp(dest2.id.script.hash.data, dest.id.script.hash.data, 20) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("script_for_destination: DEST_NONE produces empty... ");
    {
        struct tx_destination dest;
        dest.type = DEST_NONE;
        struct script s;
        script_for_destination(&s, &dest);
        bool ok = (s.size == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * tx_destination_is_valid
     * ================================================================ */
    printf("tx_destination_is_valid... ");
    {
        struct tx_destination d1 = { .type = DEST_KEY_ID };
        struct tx_destination d2 = { .type = DEST_SCRIPT_ID };
        struct tx_destination d3 = { .type = DEST_NONE };
        bool ok = tx_destination_is_valid(&d1) && tx_destination_is_valid(&d2) && !tx_destination_is_valid(&d3);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * script_sig_args_expected
     * ================================================================ */
    printf("script_sig_args_expected... ");
    {
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        bool ok = (script_sig_args_expected(TX_PUBKEY, solutions, solution_sizes, 0) == 1);
        ok = ok && (script_sig_args_expected(TX_PUBKEYHASH, solutions, solution_sizes, 0) == 2);
        ok = ok && (script_sig_args_expected(TX_SCRIPTHASH, solutions, solution_sizes, 0) == 1);
        ok = ok && (script_sig_args_expected(TX_NONSTANDARD, solutions, solution_sizes, 0) == -1);
        ok = ok && (script_sig_args_expected(TX_NULL_DATA, solutions, solution_sizes, 0) == -1);

        /* Multisig: first solution byte is m */
        solutions[0][0] = 2;
        solution_sizes[0] = 1;
        ok = ok && (script_sig_args_expected(TX_MULTISIG, solutions, solution_sizes, 1) == 3); /* m+1 = 2+1 */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * script_stack on the heap, push failures propagate.
     *
     * Before the refactor, eval_script had a ~520 KB altstack on its C
     * stack frame and verify_script added two more (~1 MB), so parallel
     * script-check workers with P2SH recursion could push thread
     * stacks past their default 8 MB cap. With items[] now
     * heap-allocated the interpreter frame is small. Stack_push
     * failures also used to be silently dropped, leaving the stack
     * shape inconsistent for subsequent OP_PICK / OP_ROLL reads.
     * ================================================================ */
    printf("deep nested OP_IF — 100 frames succeed ... ");
    {
        long rss_before_kb = ts_rss_kb();

        struct script s;
        script_init(&s);
        for (int i = 0; i < 100; i++) {
            script_push_op(&s, OP_1);
            script_push_op(&s, OP_IF);
        }
        script_push_op(&s, OP_1);
        for (int i = 0; i < 100; i++) {
            script_push_op(&s, OP_ENDIF);
        }
        struct script_stack stk __attribute__((cleanup(stack_free))) = {0};
        stack_init(&stk);
        ScriptError err;
        bool ok = eval_script(&stk, &s, 0, NULL, 0, &err);

        long ru_delta_kb = ts_rss_kb() - rss_before_kb;
        bool memory_ok = ru_delta_kb < 10 * 1024;  /* <10 MB growth */

        if (ok && stk.count == 1 && cast_to_bool(stack_top(&stk, -1)) &&
            memory_ok)
            printf("OK (rss_delta=%ld kB)\n", ru_delta_kb);
        else { printf("FAIL (ok=%d, count=%zu, err=%d, rss_delta=%ld kB)\n",
                      ok, stk.count, (int)err, ru_delta_kb); failures++; }
    }

    printf("stack_push overflow returns STACK_SIZE ... ");
    {
        /* Fill the stack to MAX_STACK_ITEMS via OP_1 pushes, then OP_DUP
         * must refuse with SCRIPT_ERR_STACK_SIZE. Pre-refactor the
         * failed stack_push returned silently and subsequent reads
         * operated on a stack shape out of sync with stack->count. */
        struct script s;
        script_init(&s);
        for (int i = 0; i < MAX_STACK_ITEMS; i++)
            script_push_op(&s, OP_1);
        script_push_op(&s, OP_DUP);
        struct script_stack stk __attribute__((cleanup(stack_free))) = {0};
        stack_init(&stk);
        ScriptError err = SCRIPT_ERR_OK;
        bool ok = eval_script(&stk, &s, 0, NULL, 0, &err);
        if (!ok && err == SCRIPT_ERR_STACK_SIZE)
            printf("OK\n");
        else { printf("FAIL (ok=%d, err=%d)\n", ok, (int)err); failures++; }
    }

    /* ================================================================
     * script_id_from_script
     * ================================================================ */
    printf("script_id_from_script: deterministic... ");
    {
        struct script s;
        s.data[0] = OP_DUP;
        s.data[1] = OP_HASH160;
        s.size = 2;

        struct script_id id1, id2;
        script_id_from_script(&id1, &s);
        script_id_from_script(&id2, &s);
        bool ok = (memcmp(id1.hash.data, id2.hash.data, 20) == 0);
        /* hash should be non-zero */
        uint8_t zeros[20] = {0};
        ok = ok && (memcmp(id1.hash.data, zeros, 20) != 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
