/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure standard-script-type detection. Replays from script bytes alone.
 * No clock, RNG, allocation, or I/O. Mirrors zclassicd
 * src/script/standard.cpp::Solver + ExtractDestination + GetScriptID. */

#include "domain/consensus/script_standard.h"

#include "core/hash.h"
#include "keys/pubkey.h"
#include "script/script.h"
#include "script/standard.h"      /* for struct tx_destination layout */

#include <string.h>

const char *domain_consensus_script_txn_output_type_name(
        enum domain_script_txnouttype t)
{
    switch (t) {
    case DOMAIN_SCRIPT_TX_NONSTANDARD: return "nonstandard";
    case DOMAIN_SCRIPT_TX_PUBKEY:      return "pubkey";
    case DOMAIN_SCRIPT_TX_PUBKEYHASH:  return "pubkeyhash";
    case DOMAIN_SCRIPT_TX_SCRIPTHASH:  return "scripthash";
    case DOMAIN_SCRIPT_TX_MULTISIG:    return "multisig";
    case DOMAIN_SCRIPT_TX_NULL_DATA:   return "nulldata";
    }
    return NULL;
}

struct zcl_result domain_consensus_script_id_from_script(
        const struct script *s,
        unsigned char out_hash[20])
{
    if (!s)
        return ZCL_ERR(DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_SCRIPT,
                       "script_id_from_script: null script");
    if (!out_hash)
        return ZCL_ERR(DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_OUT,
                       "script_id_from_script: null out_hash");
    hash160(s->data, s->size, out_hash);
    return ZCL_OK;
}

/* Return the solver null-argument error, or ZCL_OK when the pointers
 * are present and solutions_cap is non-zero. */
static struct zcl_result script_solver_check_args(
        const struct script *s,
        unsigned char solutions[][65],
        size_t solution_sizes[],
        size_t solutions_cap,
        enum domain_script_txnouttype *type_out,
        size_t *num_solutions,
        bool *matched)
{
    if (!s)
        return ZCL_ERR(DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_SCRIPT,
                       "script_solver: null script");
    if (!type_out || !num_solutions || !matched)
        return ZCL_ERR(DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_OUT,
                       "script_solver: null out pointer");
    if (!solutions || !solution_sizes || solutions_cap == 0)
        return ZCL_ERR(DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_SOLUTIONS,
                       "script_solver: null solutions buffer");
    return ZCL_OK;
}

enum {
    SCRIPT_SOLVER_PHASE_P2SH = 0,
    SCRIPT_SOLVER_PHASE_AFTER_NULL = 1
};

struct script_solver_byte_check {
    size_t offset;
    int expect;
    int expect_alt;
    int has_alt;
};

struct script_solver_template {
    size_t size;
    size_t copy_off;
    size_t copy_len;
    enum domain_script_txnouttype type;
    int phase;
    size_t nchecks;
    struct script_solver_byte_check checks[5];
};

/* Rows: size, copy_off, copy_len, type, phase, nchecks, then five
 * {offset, expect, expect_alt, has_alt} checks. nchecks of them are
 * live, in order; has_alt accepts expect or expect_alt. P2SH is tried
 * before OP_RETURN and the other rows after it. */
static const struct script_solver_template k_script_solver_templates[] = {
    /* P2SH: OP_HASH160 <20> <hash> OP_EQUAL */
    { 23, 2, 20, DOMAIN_SCRIPT_TX_SCRIPTHASH, SCRIPT_SOLVER_PHASE_P2SH, 3,
      { {0, OP_HASH160, 0, 0},
        {1, 20, 0, 0},
        {22, OP_EQUAL, 0, 0},
        {0, 0, 0, 0},
        {0, 0, 0, 0} } },
    /* P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG */
    { 25, 3, 20, DOMAIN_SCRIPT_TX_PUBKEYHASH,
      SCRIPT_SOLVER_PHASE_AFTER_NULL, 5,
      { {0, OP_DUP, 0, 0},
        {1, OP_HASH160, 0, 0},
        {2, 20, 0, 0},
        {23, OP_EQUALVERIFY, 0, 0},
        {24, OP_CHECKSIG, 0, 0} } },
    /* P2PK compressed: <33> <compressed pubkey> OP_CHECKSIG */
    { 35, 1, 33, DOMAIN_SCRIPT_TX_PUBKEY, SCRIPT_SOLVER_PHASE_AFTER_NULL, 3,
      { {0, 33, 0, 0},
        {34, OP_CHECKSIG, 0, 0},
        {1, 0x02, 0x03, 1},
        {0, 0, 0, 0},
        {0, 0, 0, 0} } },
    /* P2PK uncompressed: <65> <04 pubkey> OP_CHECKSIG */
    { 67, 1, 65, DOMAIN_SCRIPT_TX_PUBKEY, SCRIPT_SOLVER_PHASE_AFTER_NULL, 3,
      { {0, 65, 0, 0},
        {66, OP_CHECKSIG, 0, 0},
        {1, 0x04, 0, 0},
        {0, 0, 0, 0},
        {0, 0, 0, 0} } },
};

/* True when s has the template size and passes each live byte check. */
static bool script_solver_template_matches(
        const struct script *s,
        const struct script_solver_template *t)
{
    if (s->size != t->size)
        return false;
    for (size_t i = 0; i < t->nchecks; i++) {
        const struct script_solver_byte_check *c = &t->checks[i];
        int b = s->data[c->offset];
        if (b != c->expect && (!c->has_alt || b != c->expect_alt))
            return false;
    }
    return true;
}

/* Return true when a template in phase matches. Write its one solution
 * when solutions_cap is at least 1. */
static bool script_solver_take_template(
        const struct script *s,
        unsigned char solutions[][65],
        size_t solution_sizes[],
        size_t solutions_cap,
        enum domain_script_txnouttype *type_out,
        size_t *num_solutions,
        bool *matched,
        int phase)
{
    *num_solutions = 0;
    *matched = false;
    *type_out = DOMAIN_SCRIPT_TX_NONSTANDARD;
    for (size_t i = 0; i < sizeof k_script_solver_templates /
                             sizeof k_script_solver_templates[0]; i++) {
        const struct script_solver_template *t = &k_script_solver_templates[i];
        if (t->phase == phase && script_solver_template_matches(s, t)) {
            if (solutions_cap < 1) return true;  /* graceful: NONSTANDARD */
            *type_out = t->type;
            memcpy(solutions[0], s->data + t->copy_off, t->copy_len);
            solution_sizes[0] = t->copy_len;
            *num_solutions = 1;
            *matched = true;
            return true;
        }
    }
    return false;
}

/* True when bytes from offset 1 are direct pushes or PUSHDATA opcodes
 * whose length prefix fits in the script. */
static bool script_solver_nulldata_pushes_ok(const struct script *s)
{
    size_t i = 1;
    while (i < s->size) {
        unsigned char op = s->data[i];
        if (op <= 0x4e) {
            size_t push_len = 0;
            if (op <= 75) {
                push_len = op;
                i++;
            } else if (op == OP_PUSHDATA1 && i + 1 < s->size) {
                push_len = s->data[i + 1];
                i += 2;
            } else if (op == OP_PUSHDATA2 && i + 2 < s->size) {
                push_len = s->data[i + 1] |
                           ((size_t)s->data[i + 2] << 8);
                i += 3;
            } else if (op == OP_PUSHDATA4 && i + 4 < s->size) {
                push_len = s->data[i + 1] |
                           ((size_t)s->data[i + 2] << 8) |
                           ((size_t)s->data[i + 3] << 16) |
                           ((size_t)s->data[i + 4] << 24);
                i += 5;
            } else {
                return false;
            }
            i += push_len;
        } else {
            return false;
        }
    }
    return true;
}

struct script_solver_multisig_mn {
    int m;
    int n;
    bool ok;
};

/* Fill m and n from an OP_m ... OP_n OP_CHECKMULTISIG frame with
 * 1 <= m <= n; otherwise ok is false. */
static struct script_solver_multisig_mn script_solver_multisig_counts(
        const struct script *s)
{
    struct script_solver_multisig_mn mn = {0, 0, false};
    if (s->size >= 4 && s->data[s->size - 1] == OP_CHECKMULTISIG) {
        unsigned char last_op = s->data[s->size - 2];
        if (last_op >= OP_1 && last_op <= OP_16) {
            int n = last_op - (OP_1 - 1);
            unsigned char first_op = s->data[0];
            if (first_op >= OP_1 && first_op <= OP_16) {
                int m = first_op - (OP_1 - 1);
                if (m >= 1 && n >= 1 && m <= n) {
                    mn.m = m;
                    mn.n = n;
                    mn.ok = true;
                }
            }
        }
    }
    return mn;
}

/* Copy up to n 33- or 65-byte pushes from offset 1 into solutions[1..]
 * and write the stopping cursor to *pos_out. Return how many were copied. */
static int script_solver_read_multisig_keys(
        const struct script *s,
        int n,
        unsigned char solutions[][65],
        size_t solution_sizes[],
        size_t *pos_out)
{
    size_t pos = 1;
    int key_count = 0;
    *pos_out = pos;
    while (key_count < n && pos < s->size - 2) {
        unsigned char klen = s->data[pos];
        if (klen != 33 && klen != 65) break;
        pos++;
        if (pos + klen > s->size - 2) break;
        memcpy(solutions[key_count + 1], s->data + pos, klen);
        solution_sizes[key_count + 1] = klen;
        pos += klen;
        key_count++;
    }
    *pos_out = pos;
    return key_count;
}

/* Return true and write the M byte, pubkey pushes, and N byte when s
 * is an M-of-N multisig that fits in the solution buffer. */
static bool script_solver_match_multisig(
        const struct script *s,
        unsigned char solutions[][65],
        size_t solution_sizes[],
        size_t solutions_cap,
        enum domain_script_txnouttype *type_out,
        size_t *num_solutions,
        bool *matched)
{
    struct script_solver_multisig_mn mn;

    *num_solutions = 0;
    *matched = false;
    *type_out = DOMAIN_SCRIPT_TX_NONSTANDARD;
    mn = script_solver_multisig_counts(s);
    /* Multisig: OP_m <pubkey>{n} OP_n OP_CHECKMULTISIG */
    if (mn.ok) {
        int m = mn.m;
        int n = mn.n;
        /* Need n + 2 rows (M-byte, n keys, N-byte).
         * If the caller's buffer is too small, gracefully
         * fall through to NONSTANDARD — never overrun. */
        if ((size_t)(n + 2) > solutions_cap) {
            *num_solutions = 0;
            return false;
        }
        size_t pos = 0;
        solutions[0][0] = (unsigned char)m;
        solution_sizes[0] = 1;
        *num_solutions = 1;
        int key_count = script_solver_read_multisig_keys(
                s, n, solutions, solution_sizes, &pos);
        if (key_count == n && pos == s->size - 2) {
            *num_solutions = (size_t)key_count + 1;
            solutions[*num_solutions][0] = (unsigned char)n;
            solution_sizes[*num_solutions] = 1;
            (*num_solutions)++;
            *type_out = DOMAIN_SCRIPT_TX_MULTISIG;
            *matched = true;
            return true;
        }
        *num_solutions = 0;
    }
    return false;
}

struct zcl_result domain_consensus_script_solver(
        const struct script *s,
        unsigned char solutions[][65],
        size_t solution_sizes[],
        size_t solutions_cap,
        enum domain_script_txnouttype *type_out,
        size_t *num_solutions,
        bool *matched)
{
    struct zcl_result r = script_solver_check_args(
            s, solutions, solution_sizes, solutions_cap,
            type_out, num_solutions, matched);
    if (!r.ok)
        return r;

    *num_solutions = 0;
    *matched       = false;
    *type_out      = DOMAIN_SCRIPT_TX_NONSTANDARD;

    if (script_solver_take_template(
                s, solutions, solution_sizes, solutions_cap,
                type_out, num_solutions, matched,
                SCRIPT_SOLVER_PHASE_P2SH))
        return ZCL_OK;

    /* OP_RETURN (null data) — match must consume entire script as
     * legal data pushes. */
    if (s->size >= 1 && s->data[0] == OP_RETURN) {
        if (script_solver_nulldata_pushes_ok(s)) {
            *type_out = DOMAIN_SCRIPT_TX_NULL_DATA;
            *matched = true;
            return ZCL_OK;
        }
        /* fall through to other patterns */
    }

    if (script_solver_take_template(
                s, solutions, solution_sizes, solutions_cap,
                type_out, num_solutions, matched,
                SCRIPT_SOLVER_PHASE_AFTER_NULL))
        return ZCL_OK;

    if (script_solver_match_multisig(
                s, solutions, solution_sizes, solutions_cap,
                type_out, num_solutions, matched))
        return ZCL_OK;

    *type_out = DOMAIN_SCRIPT_TX_NONSTANDARD;
    *matched  = false;
    return ZCL_OK;
}

int domain_consensus_script_sig_args_expected(
        enum domain_script_txnouttype t,
        const unsigned char solutions[][65],
        const size_t solution_sizes[],
        size_t num_solutions)
{
    (void)solutions;
    switch (t) {
    case DOMAIN_SCRIPT_TX_NONSTANDARD:
    case DOMAIN_SCRIPT_TX_NULL_DATA:
        return -1;
    case DOMAIN_SCRIPT_TX_PUBKEY:
        return 1;
    case DOMAIN_SCRIPT_TX_PUBKEYHASH:
        return 2;
    case DOMAIN_SCRIPT_TX_MULTISIG:
        if (!solutions || !solution_sizes ||
            num_solutions < 1 || solution_sizes[0] < 1)
            return -1;
        return solutions[0][0] + 1;
    case DOMAIN_SCRIPT_TX_SCRIPTHASH:
        return 1;
    }
    return -1;
}

struct zcl_result domain_consensus_script_extract_destination(
        const struct script *s,
        struct tx_destination *dest_out,
        bool *matched)
{
    if (!s)
        return ZCL_ERR(DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_SCRIPT,
                       "extract_destination: null script");
    if (!dest_out || !matched)
        return ZCL_ERR(DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_OUT,
                       "extract_destination: null out pointer");

    *matched = false;
    dest_out->type = DEST_NONE;

    enum domain_script_txnouttype type;
    unsigned char solutions[20][65];
    size_t solution_sizes[20];
    size_t num_solutions = 0;
    bool solver_matched = false;

    struct zcl_result r = domain_consensus_script_solver(
            s, solutions, solution_sizes, 20,
            &type, &num_solutions, &solver_matched);
    if (!r.ok) return r;
    if (!solver_matched) return ZCL_OK;

    if (type == DOMAIN_SCRIPT_TX_PUBKEY) {
        struct pubkey pk;
        pubkey_set(&pk, solutions[0], solution_sizes[0]);
        if (!pubkey_is_valid(&pk))
            return ZCL_OK;
        dest_out->type = DEST_KEY_ID;
        dest_out->id.key = pubkey_get_id(&pk);
        *matched = true;
        return ZCL_OK;
    }
    if (type == DOMAIN_SCRIPT_TX_PUBKEYHASH) {
        dest_out->type = DEST_KEY_ID;
        memcpy(dest_out->id.key.id.data, solutions[0], 20);
        *matched = true;
        return ZCL_OK;
    }
    if (type == DOMAIN_SCRIPT_TX_SCRIPTHASH) {
        dest_out->type = DEST_SCRIPT_ID;
        memcpy(dest_out->id.script.hash.data, solutions[0], 20);
        *matched = true;
        return ZCL_OK;
    }
    return ZCL_OK;
}
