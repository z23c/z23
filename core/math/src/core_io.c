/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "core/core_io.h"
#include "core/serialize.h"
#include "encoding/utilstrencodings.h"
#include "encoding/utilmoneystr.h"
#include "script/standard.h"
#include "script/sigencoding.h"
#include "script/sighashtype.h"
#include "keys/key_io.h"
#include "chain/chainparams.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "util/safe_alloc.h"

static bool script_push_num(struct script *s, int64_t n)
{
    if (n == -1 || (n >= 1 && n <= 16)) {
        return script_push_op(s, (enum opcodetype)(n + (OP_1 - 1)));
    }
    if (n == 0) {
        return script_push_op(s, OP_0);
    }
    struct script_num sn = script_num_from_int(n);
    unsigned char buf[9];
    size_t len = script_num_serialize(&sn, buf, sizeof(buf));
    return script_push_data(s, buf, len);
}

struct opname_entry {
    const char *name;
    enum opcodetype op;
};

static struct opname_entry g_opnames[512];
static size_t g_num_opnames = 0;

static void init_opnames(void)
{
    if (g_num_opnames > 0) return;
    for (int op = 0; op < FIRST_UNDEFINED_OP_VALUE; op++) {
        if (op < OP_NOP && op != OP_RESERVED)
            continue;
        const char *name = script_get_op_name((enum opcodetype)op);
        if (strcmp(name, "OP_UNKNOWN") == 0)
            continue;
        g_opnames[g_num_opnames].name = name;
        g_opnames[g_num_opnames].op = (enum opcodetype)op;
        g_num_opnames++;
    }
}

static bool find_opcode(const char *token, enum opcodetype *out)
{
    init_opnames();
    for (size_t i = 0; i < g_num_opnames; i++) {
        if (strcmp(g_opnames[i].name, token) == 0) {
            *out = g_opnames[i].op;
            return true;
        }
        if (strncmp(g_opnames[i].name, "OP_", 3) == 0 &&
            strcmp(g_opnames[i].name + 3, token) == 0) {
            *out = g_opnames[i].op;
            return true;
        }
    }
    return false;
}

static bool str_is_digits(const char *s)
{
    if (!*s) return false;
    for (const char *p = s; *p; p++)
        if (!isdigit((unsigned char)*p)) return false;
    return true;
}

enum script_tok_status {
    SCRIPT_TOK_FAIL = 0,
    SCRIPT_TOK_OK = 1,
    SCRIPT_TOK_STOP = -1,
    SCRIPT_TOK_SKIP = 2
};

/* Copy a 0x hex token into out: SKIP if not hex, STOP if over MAX_SCRIPT_SIZE, OK when copied. */
static int parse_script_hex_token(struct script *out, const char *token)
{
    if (strncmp(token, "0x", 2) == 0 && token[2] && IsHex(token + 2)) {
        size_t hex_len = strlen(token + 2);
        size_t byte_len = hex_len / 2;
        if (byte_len > MAX_SCRIPT_SIZE || out->size + byte_len > MAX_SCRIPT_SIZE)
            return SCRIPT_TOK_STOP;
        unsigned char raw[MAX_SCRIPT_SIZE];
        ParseHex(token + 2, raw, byte_len);
        memcpy(out->data + out->size, raw, byte_len);
        out->size += byte_len;
        return SCRIPT_TOK_OK;
    }
    return SCRIPT_TOK_SKIP;
}

/* Parse a numeric or 0x token: OK, FAIL, STOP, or SKIP when it is neither. */
static int parse_script_num_or_hex(struct script *out, const char *token)
{
    bool is_neg = token[0] == '-';
    const char *num_start = is_neg ? token + 1 : token;

    if (str_is_digits(num_start) && *num_start) {
        int64_t n = strtoll(token, NULL, 10);
        if (script_push_num(out, n))
            return SCRIPT_TOK_OK;
        return SCRIPT_TOK_FAIL;
    }

    return parse_script_hex_token(out, token);
}

/* Push a single-quoted token: SKIP if not quoted, else OK or FAIL as script_push_data reports. */
static int parse_script_quoted_token(struct script *out, const char *token)
{
    if (token[0] == '\'' && token[strlen(token)-1] == '\'' &&
        strlen(token) >= 2) {
        size_t len = strlen(token) - 2;
        if (script_push_data(out, (const unsigned char *)(token + 1), len))
            return SCRIPT_TOK_OK;
        return SCRIPT_TOK_FAIL;
    }
    return SCRIPT_TOK_SKIP;
}

/* Push a named opcode: OK when the push succeeds, FAIL when the name is unknown or the push does not fit. */
static int parse_script_opcode_token(struct script *out, const char *token)
{
    enum opcodetype op;
    if (find_opcode(token, &op))
        return script_push_op(out, op) ? SCRIPT_TOK_OK : SCRIPT_TOK_FAIL;
    return SCRIPT_TOK_FAIL;
}

bool parse_script(const char *asm_str, struct script *out)
{
    script_init(out);
    if (!asm_str || !*asm_str) return true;

    char *buf = strdup(asm_str);
    if (!buf) return false;

    char *saveptr;
    char *token = strtok_r(buf, " \t\n", &saveptr);
    bool ok = true;

    while (token && ok) {
        if (!*token) {
            token = strtok_r(NULL, " \t\n", &saveptr);
            continue;
        }
        int st = parse_script_num_or_hex(out, token);
        if (st == SCRIPT_TOK_STOP) {
            ok = false;
            break;
        }
        if (st == SCRIPT_TOK_SKIP)
            st = parse_script_quoted_token(out, token);
        if (st == SCRIPT_TOK_SKIP)
            st = parse_script_opcode_token(out, token);
        ok = st == SCRIPT_TOK_OK;
        token = strtok_r(NULL, " \t\n", &saveptr);
    }
    free(buf);
    return ok;
}

static const char *sighash_type_name(unsigned char type)
{
    switch (type) {
    case SIGHASH_ALL: return "ALL";
    case SIGHASH_ALL | SIGHASH_ANYONECANPAY: return "ALL|ANYONECANPAY";
    case SIGHASH_NONE: return "NONE";
    case SIGHASH_NONE | SIGHASH_ANYONECANPAY: return "NONE|ANYONECANPAY";
    case SIGHASH_SINGLE: return "SINGLE";
    case SIGHASH_SINGLE | SIGHASH_ANYONECANPAY: return "SINGLE|ANYONECANPAY";
    default: return NULL;
    }
}

/* Write text at pos through snprintf clamped to out_size, and return pos plus that result. */
static size_t script_asm_append(char *out, size_t out_size, size_t pos,
                                const char *text)
{
    size_t n = (size_t)snprintf(out + (pos < out_size ? pos : out_size - 1),
                                pos < out_size ? out_size - pos : 1,
                                "%s", text);
    return pos + n;
}

/* Format data as a decimal script number, or as hex when it is not one. */
static size_t script_asm_push_small(char *out, size_t out_size, size_t pos,
                                    const unsigned char *data, size_t datalen)
{
    struct script_num sn;
    if (script_num_from_bytes(&sn, data, datalen,
                              false, 4)) {
        int n = script_num_get_int(&sn);
        char num[32];
        snprintf(num, sizeof(num), "%d", n);
        return script_asm_append(out, out_size, pos, num);
    }
    char hex[MAX_SCRIPT_ELEMENT_SIZE * 2 + 1];
    HexStr(data, datalen, false, hex, sizeof(hex));
    return script_asm_append(out, out_size, pos, hex);
}

/* Write data in hex. When the sighash checks yield a name, write the leading bytes and that name. */
static size_t script_asm_push_long(char *out, size_t out_size, size_t pos,
                                   const struct script *s,
                                   const unsigned char *data, size_t datalen,
                                   bool attempt_sighash_decode)
{
    char hex[MAX_SCRIPT_ELEMENT_SIZE * 2 + 1];
    HexStr(data, datalen, false, hex, sizeof(hex));

    if (attempt_sighash_decode && !script_is_unspendable(s)) {
        if (check_transaction_signature_encoding(
                data, datalen, SCRIPT_VERIFY_STRICTENC, NULL)) {
            unsigned char ht = data[datalen - 1];
            const char *tn = sighash_type_name(ht);
            if (tn) {
                char hex2[MAX_SCRIPT_ELEMENT_SIZE * 2 + 1];
                HexStr(data, datalen - 1, false, hex2, sizeof(hex2));
                char rendered[MAX_SCRIPT_ELEMENT_SIZE * 2 + 64];
                snprintf(rendered, sizeof(rendered), "%s[%s]", hex2, tn);
                return script_asm_append(out, out_size, pos, rendered);
            }
        }
    }
    return script_asm_append(out, out_size, pos, hex);
}

/* Write the terminating NUL when out_size allows it. */
static void script_asm_terminate(char *out, size_t out_size, size_t pos)
{
    if (pos < out_size)
        out[pos] = '\0';
    else if (out_size > 0)
        out[out_size - 1] = '\0';
}

size_t script_to_asm_str(const struct script *s, bool attempt_sighash_decode,
                         char *out, size_t out_size)
{
    size_t pos = 0;
    size_t pc = 0;
    enum opcodetype opcode;
    unsigned char data[MAX_SCRIPT_ELEMENT_SIZE];
    size_t datalen;

    while (pc < s->size) {
        if (pos > 0 && pos < out_size)
            out[pos] = ' ';
        if (pos > 0) pos++;

        datalen = 0;
        if (!script_get_op(s, &pc, &opcode, data, &datalen)) {
            pos = script_asm_append(out, out_size, pos, "[error]");
            break;
        }

        if (opcode >= 0 && opcode <= OP_PUSHDATA4) {
            if (datalen <= 4)
                pos = script_asm_push_small(out, out_size, pos, data, datalen);
            else
                pos = script_asm_push_long(out, out_size, pos, s, data,
                                           datalen, attempt_sighash_decode);
        } else {
            const char *name = script_get_op_name(opcode);
            pos = script_asm_append(out, out_size, pos, name);
        }
    }
    script_asm_terminate(out, out_size, pos);
    return pos;
}

bool decode_hex_tx(struct transaction *tx, const char *hex_str)
{
    if (!IsHex(hex_str)) return false;
    size_t hex_len = strlen(hex_str);
    size_t byte_len = hex_len / 2;
    unsigned char *raw = zcl_malloc(byte_len, "decode_hex_tx");
    if (!raw) return false;
    ParseHex(hex_str, raw, byte_len);

    struct byte_stream s;
    stream_init_from_data(&s, raw, byte_len);
    bool ok = transaction_deserialize(tx, &s);
    free(raw);
    return ok;
}

bool parse_hash_str(const char *hex_str, struct uint256 *out)
{
    if (!hex_str || !IsHex(hex_str)) return false;
    if (strlen(hex_str) != 64) return false;
    uint256_set_hex(out, hex_str);
    return true;
}

size_t encode_hex_tx(const struct transaction *tx, char *out, size_t out_size)
{
    struct byte_stream s;
    stream_init(&s, 256);
    transaction_serialize(tx, &s);
    size_t hex_len = s.size * 2;
    if (out_size > 0) {
        size_t to_encode = s.size;
        if (hex_len + 1 > out_size)
            to_encode = (out_size - 1) / 2;
        HexStr(s.data, to_encode, false, out, out_size);
    }
    stream_free(&s);
    return hex_len;
}

void script_pub_key_to_json(const struct script *script_pub_key,
                            struct json_value *out, bool include_hex)
{
    json_init(out);
    json_set_object(out);

    char asm_str[4096];
    script_to_asm_str(script_pub_key, false, asm_str, sizeof(asm_str));
    json_push_kv_str(out, "asm", asm_str);

    if (include_hex) {
        char hex[MAX_SCRIPT_SIZE * 2 + 1];
        HexStr(script_pub_key->data, script_pub_key->size, false,
               hex, sizeof(hex));
        json_push_kv_str(out, "hex", hex);
    }

    enum txnouttype type;
    unsigned char solutions[16][65];
    size_t solution_sizes[16];
    size_t num_solutions = 0;
    script_solver(script_pub_key, &type, solutions, solution_sizes,
                  &num_solutions);
    json_push_kv_str(out, "type", get_txn_output_type(type));

    struct tx_destination dest;
    if (script_extract_destination(script_pub_key, &dest)) {
        if (type == TX_MULTISIG) {
            json_push_kv_int(out, "reqSigs",
                             script_decode_op_n(
                                 (enum opcodetype)script_pub_key->data[0]));
        } else {
            json_push_kv_int(out, "reqSigs", 1);
        }

        struct json_value addrs;
        json_init(&addrs);
        json_set_array(&addrs);

        const struct chain_params *params = chain_params_get();
        size_t pk_len, sc_len;
        const unsigned char *pk_pfx = chain_params_base58_prefix(
            params, B58_PUBKEY_ADDRESS, &pk_len);
        const unsigned char *sc_pfx = chain_params_base58_prefix(
            params, B58_SCRIPT_ADDRESS, &sc_len);
        char addr[128];
        if (encode_destination(&dest, pk_pfx, pk_len,
                               sc_pfx, sc_len,
                               addr, sizeof(addr))) {
            struct json_value av;
            json_init(&av);
            json_set_str(&av, addr);
            json_push_back(&addrs, &av);
            json_free(&av);
        }
        json_push_kv(out, "addresses", &addrs);
        json_free(&addrs);
    }
}

void tx_to_json(const struct transaction *tx,
                const struct uint256 *hash_block,
                struct json_value *entry)
{
    json_init(entry);
    json_set_object(entry);

    char hash_hex[65];
    uint256_get_hex(&tx->hash, hash_hex);
    json_push_kv_str(entry, "txid", hash_hex);
    json_push_kv_int(entry, "version", tx->version);
    json_push_kv_int(entry, "locktime", (int64_t)tx->lock_time);

    struct json_value vin_arr;
    json_init(&vin_arr);
    json_set_array(&vin_arr);

    for (size_t i = 0; i < tx->num_vin; i++) {
        const struct tx_in *txin = &tx->vin[i];
        struct json_value in;
        json_init(&in);
        json_set_object(&in);

        if (transaction_is_coinbase(tx)) {
            char sig_hex[MAX_SCRIPT_SIZE * 2 + 1];
            HexStr(txin->script_sig.data, txin->script_sig.size,
                   false, sig_hex, sizeof(sig_hex));
            json_push_kv_str(&in, "coinbase", sig_hex);
        } else {
            char txid_hex[65];
            uint256_get_hex(&txin->prevout.hash, txid_hex);
            json_push_kv_str(&in, "txid", txid_hex);
            json_push_kv_int(&in, "vout", (int64_t)txin->prevout.n);

            struct json_value script_obj;
            json_init(&script_obj);
            json_set_object(&script_obj);

            char asm_str[4096];
            script_to_asm_str(&txin->script_sig, true, asm_str, sizeof(asm_str));
            json_push_kv_str(&script_obj, "asm", asm_str);

            char sig_hex[MAX_SCRIPT_SIZE * 2 + 1];
            HexStr(txin->script_sig.data, txin->script_sig.size,
                   false, sig_hex, sizeof(sig_hex));
            json_push_kv_str(&script_obj, "hex", sig_hex);

            json_push_kv(&in, "scriptSig", &script_obj);
            json_free(&script_obj);
        }
        json_push_kv_int(&in, "sequence", (int64_t)txin->sequence);
        json_push_back(&vin_arr, &in);
        json_free(&in);
    }
    json_push_kv(entry, "vin", &vin_arr);
    json_free(&vin_arr);

    struct json_value vout_arr;
    json_init(&vout_arr);
    json_set_array(&vout_arr);

    for (size_t i = 0; i < tx->num_vout; i++) {
        const struct tx_out *txout = &tx->vout[i];
        struct json_value out_obj;
        json_init(&out_obj);
        json_set_object(&out_obj);

        char money[32];
        FormatMoney(txout->value, money, sizeof(money));
        json_push_kv_str(&out_obj, "value", money);
        json_push_kv_int(&out_obj, "n", (int64_t)i);

        struct json_value spk;
        script_pub_key_to_json(&txout->script_pub_key, &spk, true);
        json_push_kv(&out_obj, "scriptPubKey", &spk);
        json_free(&spk);

        json_push_back(&vout_arr, &out_obj);
        json_free(&out_obj);
    }
    json_push_kv(entry, "vout", &vout_arr);
    json_free(&vout_arr);

    if (hash_block && !uint256_is_null(hash_block)) {
        char bh[65];
        uint256_get_hex(hash_block, bh);
        json_push_kv_str(entry, "blockhash", bh);
    }

    size_t hex_len = encode_hex_tx(tx, NULL, 0);  /* measuring mode: s.size*2 */
    char *hex_buf = zcl_malloc(hex_len + 1, "tx_hex_buf");
    if (hex_buf) {
        encode_hex_tx(tx, hex_buf, hex_len + 1);
        json_push_kv_str(entry, "hex", hex_buf);
        free(hex_buf);
    }
}
