/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_SCRIPT_SCRIPT_H
#define ZCL_SCRIPT_SCRIPT_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define MAX_SCRIPT_ELEMENT_SIZE 520
#define MAX_SCRIPT_SIZE 10000
#define LOCKTIME_THRESHOLD 500000000

enum opcodetype {
    OP_0 = 0x00,
    OP_PUSHDATA1 = 0x4c, OP_PUSHDATA2 = 0x4d, OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f, OP_RESERVED = 0x50,
    OP_1 = 0x51, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8,
    OP_9, OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, OP_16,
    OP_NOP = 0x61, OP_VER, OP_IF, OP_NOTIF, OP_VERIF, OP_VERNOTIF,
    OP_ELSE, OP_ENDIF, OP_VERIFY, OP_RETURN,
    OP_TOALTSTACK = 0x6b, OP_FROMALTSTACK, OP_2DROP, OP_2DUP, OP_3DUP,
    OP_2OVER, OP_2ROT, OP_2SWAP, OP_IFDUP, OP_DEPTH, OP_DROP, OP_DUP,
    OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SWAP, OP_TUCK,
    OP_CAT = 0x7e, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_SIZE,
    OP_INVERT = 0x83, OP_AND, OP_OR, OP_XOR,
    OP_EQUAL, OP_EQUALVERIFY, OP_RESERVED1, OP_RESERVED2,
    OP_1ADD = 0x8b, OP_1SUB, OP_2MUL, OP_2DIV,
    OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL,
    OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT,
    OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL, OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN,
    OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX,
    OP_WITHIN = 0xa5,
    OP_RIPEMD160 = 0xa6, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256,
    OP_CODESEPARATOR, OP_CHECKSIG, OP_CHECKSIGVERIFY,
    OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY,
    OP_NOP1 = 0xb0, OP_NOP2, OP_NOP3, OP_NOP4, OP_NOP5,
    OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10,
    OP_CHECKDATASIG = 0xba, OP_CHECKDATASIGVERIFY,
    OP_SMALLINTEGER = 0xfa, OP_PUBKEYS = 0xfb,
    OP_PUBKEYHASH = 0xfd, OP_PUBKEY = 0xfe,
    OP_INVALIDOPCODE = 0xff,
};

#define OP_FALSE OP_0
#define OP_TRUE OP_1
#define OP_CHECKLOCKTIMEVERIFY OP_NOP2

struct script {
    unsigned char data[MAX_SCRIPT_SIZE];
    size_t size;
};

static inline void script_init(struct script *s) { s->size = 0; }

static inline void script_set(struct script *s,
                              const unsigned char *data, size_t len)
{
    if (len > MAX_SCRIPT_SIZE) len = MAX_SCRIPT_SIZE;
    memcpy(s->data, data, len);
    s->size = len;
}

static inline bool script_push_op(struct script *s, enum opcodetype op)
{
    if (s->size >= MAX_SCRIPT_SIZE) return false;
    s->data[s->size++] = (unsigned char)op;
    return true;
}

static inline bool script_push_data(struct script *s,
                                    const unsigned char *data, size_t len)
{
    if (len < OP_PUSHDATA1) {
        if (s->size + 1 + len > MAX_SCRIPT_SIZE) return false;
        s->data[s->size++] = (unsigned char)len;
    } else if (len <= 0xff) {
        if (s->size + 2 + len > MAX_SCRIPT_SIZE) return false;
        s->data[s->size++] = OP_PUSHDATA1;
        s->data[s->size++] = (unsigned char)len;
    } else if (len <= 0xffff) {
        if (s->size + 3 + len > MAX_SCRIPT_SIZE) return false;
        s->data[s->size++] = OP_PUSHDATA2;
        s->data[s->size++] = (unsigned char)(len & 0xff);
        s->data[s->size++] = (unsigned char)(len >> 8);
    } else {
        if (s->size + 5 + len > MAX_SCRIPT_SIZE) return false;
        s->data[s->size++] = OP_PUSHDATA4;
        s->data[s->size++] = (unsigned char)(len & 0xff);
        s->data[s->size++] = (unsigned char)((len >> 8) & 0xff);
        s->data[s->size++] = (unsigned char)((len >> 16) & 0xff);
        s->data[s->size++] = (unsigned char)((len >> 24) & 0xff);
    }
    memcpy(s->data + s->size, data, len);
    s->size += len;
    return true;
}

static inline bool script_is_p2sh(const struct script *s)
{
    return s->size == 23 &&
           s->data[0] == OP_HASH160 &&
           s->data[1] == 0x14 &&
           s->data[22] == OP_EQUAL;
}

static inline bool script_is_p2pkh(const struct script *s)
{
    return s->size == 25 &&
           s->data[0] == OP_DUP &&
           s->data[1] == OP_HASH160 &&
           s->data[2] == 0x14 &&
           s->data[23] == OP_EQUALVERIFY &&
           s->data[24] == OP_CHECKSIG;
}

static inline int script_decode_op_n(enum opcodetype op)
{
    if (op == OP_0) return 0;
    return (int)(op - (OP_1 - 1));
}

#define FIRST_UNDEFINED_OP_VALUE 0xbc

/* Match Bitcoin Core CScript::IsUnspendable() exactly:
 * (size() > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE) */
static inline bool script_is_unspendable(const struct script *s)
{
    return (s->size > 0 && s->data[0] == OP_RETURN) ||
           (s->size > MAX_SCRIPT_SIZE);
}

/* Every cursor step below MUST advance `i` strictly, on every input. The
 * loop's only exit is i >= s->size, and the bytes are peer-supplied: a step
 * that computes an advance of zero spins forever inside consensus code
 * (core/consensus/src/script_interp.c reads this for the P2SH push-only
 * rule). Each branch adds a small constant to a push length, so the width
 * that addition is performed at is what decides whether it can wrap to
 * zero:
 *
 *   op < OP_PUSHDATA1  `1 + op`  — unsigned char promotes to int; op <= 75,
 *                                  so the sum is at most 76.
 *   OP_PUSHDATA1       `2 + d`   — unsigned char promotes to int; at most 257.
 *   OP_PUSHDATA2       `3 + len` — uint16_t promotes to int; at most 65538.
 *   OP_PUSHDATA4       `5 + len` — uint32_t does NOT promote to int. The
 *                                  constant converts to unsigned int and the
 *                                  sum is taken modulo 2^32 BEFORE it ever
 *                                  reaches the 64-bit `i`.
 *
 * Only the last one has an operand as wide as the arithmetic, so only the
 * last one can wrap — and the wrap is KEPT ON PURPOSE. For every length
 * whose 32-bit advance is non-zero, that advance is what produces the
 * verdict this function gives today, and four of them (0xFFFFFFFC through
 * 0xFFFFFFFF) advance the cursor by 1..4 onto a length byte above OP_16
 * and return false. Performing the addition at cursor width instead would
 * carry all four past s->size and return true — accepting a scriptSig the
 * reference implementation rejects, which is a fork, not a repair.
 *
 * Exactly one length, 0xFFFFFFFB, makes the 32-bit advance zero. It is the
 * only input for which this function produces no verdict at all rather
 * than a wrong one, so refusing it outright is the whole fix: every
 * pre-existing answer is preserved bit-for-bit and the single missing one
 * is supplied. false is also what the reference returns there, so the one
 * newly decided case lands on parity rather than away from it.
 *
 * A push whose length runs past the end of the script leaves i >= s->size
 * and yields true here, where the reference implementation's IsPushOnly
 * yields false (its GetOp refuses the truncated push); 0xFFFFFFF9 and
 * 0xFFFFFFFA are that case. The divergence is deliberate and untouched: it
 * decides transaction validity, so closing it requires a full-history
 * replay against the real chain first. */
static inline bool script_is_push_only(const struct script *s)
{
    size_t i = 0;
    while (i < s->size) {
        unsigned char op = s->data[i];
        if (op > OP_16)
            return false;
        if (op < OP_PUSHDATA1) {
            i += 1 + op;
        } else if (op == OP_PUSHDATA1) {
            if (i + 1 >= s->size) return false;
            i += 2 + s->data[i + 1];
        } else if (op == OP_PUSHDATA2) {
            if (i + 2 >= s->size) return false;
            uint16_t len = (uint16_t)s->data[i+1] | ((uint16_t)s->data[i+2] << 8);
            i += 3 + len;
        } else if (op == OP_PUSHDATA4) {
            if (i + 4 >= s->size) return false;
            uint32_t len = (uint32_t)s->data[i+1] | ((uint32_t)s->data[i+2] << 8) |
                           ((uint32_t)s->data[i+3] << 16) | ((uint32_t)s->data[i+4] << 24);
            /* Deliberately 32-bit: preserves every pre-existing verdict. */
            uint32_t adv = 5u + len;
            if (adv == 0) return false;   /* the one input with no verdict */
            i += adv;
        } else {
            i++;
        }
    }
    return true;
}

static inline bool script_get_op(const struct script *s, size_t *pc,
                                 enum opcodetype *opcode,
                                 unsigned char *data, size_t *datalen)
{
    if (*pc >= s->size)
        return false;
    unsigned char op = s->data[*pc];
    (*pc)++;
    *opcode = (enum opcodetype)op;
    if (datalen) *datalen = 0;

    if (op <= OP_PUSHDATA4) {
        size_t nsize = 0;
        if (op < OP_PUSHDATA1) {
            nsize = op;
        } else if (op == OP_PUSHDATA1) {
            if (*pc >= s->size) return false;
            nsize = s->data[*pc]; (*pc)++;
        } else if (op == OP_PUSHDATA2) {
            if (*pc + 1 >= s->size) return false;
            nsize = (size_t)s->data[*pc] | ((size_t)s->data[*pc+1] << 8);
            *pc += 2;
        } else if (op == OP_PUSHDATA4) {
            if (*pc + 3 >= s->size) return false;
            nsize = (size_t)s->data[*pc] | ((size_t)s->data[*pc+1] << 8) |
                    ((size_t)s->data[*pc+2] << 16) | ((size_t)s->data[*pc+3] << 24);
            *pc += 4;
        }
        if (*pc + nsize > s->size) return false;
        if (data && datalen) {
            /* Destination-capacity contract: every payload-receiving
             * caller passes a MAX_SCRIPT_ELEMENT_SIZE (520) stack buffer,
             * so an oversized push must be rejected BEFORE the copy.
             * data==NULL callers still traverse oversized pushes
             * faithfully — script_get_sig_op_count walks data-less,
             * matching zclassicd GetSigOpCount's full-script GetOp walk.
             * (script_get_sig_op_count_p2sh passes a payload buffer and
             * returns 0 at an oversized scriptSig push — verdict-neutral:
             * such an input fails EvalScript in both implementations.)
             * Eval side effect: a >520 push now fails parse here, so
             * eval_script reports SCRIPT_ERR_BAD_OPCODE instead of
             * SCRIPT_ERR_PUSH_SIZE; both reject, and the code is never
             * compared — it is persisted only as a diagnostic integer
             * in script_validate_log. */
            if (nsize > MAX_SCRIPT_ELEMENT_SIZE) return false;
            memcpy(data, s->data + *pc, nsize);
            *datalen = nsize;
        }
        *pc += nsize;
    }
    return true;
}

#define SCRIPT_NUM_DEFAULT_MAX_SIZE 4
#define SCRIPT_NUM_MAX_SIZE 8

struct script_num {
    int64_t value;
};

static inline struct script_num script_num_from_int(int64_t n)
{
    return (struct script_num){n};
}

/* Decode a little-endian, sign-magnitude CScriptNum from raw stack bytes.
 * CONSENSUS-relevant: this is how the VM interprets a stack element as a
 * number (OP_ADD, OP_PICK count, CLTV locktime, multisig key/sig counts, ...).
 *
 * Returns false (rejecting the element) when:
 *   - len > max_size — the magnitude is too wide. Callers pass
 *     SCRIPT_NUM_DEFAULT_MAX_SIZE (4) for ordinary arithmetic and a larger
 *     bound (e.g. 5) only where the protocol permits it, such as the CLTV
 *     locktime operand. Never widen max_size to "make a script parse".
 *   - `require_minimal` is true AND the bytes are non-minimally encoded
 *     (a redundant trailing 0x00/0x80 sign byte). This is the BIP62 rule 4
 *     minimal-encoding check. The interpreter passes
 *     require_minimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0, so clearing
 *     SCRIPT_VERIFY_MINIMALDATA in the verify flags DISABLES this check and
 *     accepts non-minimal numbers — a consensus-visible relaxation.
 * On success `out->value` is the decoded int64 (high bit of the top byte is
 * the sign). A zero-length element decodes to 0. */
static inline bool script_num_from_bytes(struct script_num *out,
                                         const unsigned char *data, size_t len,
                                         bool require_minimal,
                                         size_t max_size)
{
    if (len > max_size)
        return false;
    if (require_minimal && len > 0) {
        if ((data[len - 1] & 0x7f) == 0) {
            if (len <= 1 || (data[len - 2] & 0x80) == 0)
                return false;
        }
    }
    if (len == 0) { out->value = 0; return true; }
    int64_t result = 0;
    for (size_t i = 0; i < len; i++)
        result |= (int64_t)data[i] << (8 * i);
    if (data[len - 1] & 0x80)
        result = -(int64_t)(result & ~((int64_t)0x80 << (8 * (len - 1))));
    out->value = result;
    return true;
}

/* Serialize a script_num into a caller-supplied buffer.
 *
 * Returns the number of bytes written, or 0 if:
 *   - value is 0 (no bytes needed — nothing written), OR
 *   - the required byte length exceeds outsize (nothing written).
 *
 * The two "return 0" cases are distinguishable by the caller: if
 * sn->value != 0 and the return is 0, the buffer was too small.
 * Previously the implementation silently truncated the output on a
 * short buffer, which produced malformed byte strings downstream.
 *
 * Max output length is SCRIPT_NUM_MAX_SIZE (8 bytes): the magnitude of
 * a valid int64 never exceeds 2^63-1, whose top magnitude byte is 0x7f
 * and therefore does not require a trailing sign byte. Callers whose
 * values come from unvalidated sources should still pass the full
 * SCRIPT_NUM_MAX_SIZE rather than something smaller. */
static inline size_t script_num_serialize(const struct script_num *sn,
                                          unsigned char *out, size_t outsize)
{
    int64_t value = sn->value;
    if (value == 0) return 0;
    bool neg = value < 0;
    uint64_t absval = neg ? (uint64_t)(-value) : (uint64_t)value;

    /* Compute the required length by walking the magnitude without
     * writing. This lets us reject a short buffer atomically. */
    size_t req = 0;
    uint64_t t = absval;
    while (t) { req++; t >>= 8; }
    /* If the top magnitude byte has its high bit set, a trailing sign
     * byte is needed so the sign bit doesn't overlap the magnitude. */
    unsigned char top = (unsigned char)((absval >> (8 * (req - 1))) & 0xff);
    if (top & 0x80) req++;

    if (req > outsize) return 0;

    size_t len = 0;
    while (absval) {
        out[len++] = (unsigned char)(absval & 0xff);
        absval >>= 8;
    }
    if (out[len - 1] & 0x80)
        out[len++] = neg ? 0x80 : 0x00;
    else if (neg)
        out[len - 1] |= 0x80;

    return len;
}

static inline int script_num_get_int(const struct script_num *sn)
{
    if (sn->value > INT32_MAX) return INT32_MAX;
    if (sn->value < INT32_MIN) return INT32_MIN;
    return (int)sn->value;
}

const char *script_get_op_name(enum opcodetype opcode);

/* Count signature operations in a single script. Feeds the block-level
 * MAX_BLOCK_SIGOPS consensus limit (see core/modules/validation/src/sigops.c) and
 * the per-tx standardness check — so the count is consensus-relevant; do
 * not change it casually. Mirrors zclassicd CScript::GetSigOpCount.
 *
 * Counting rules (verified against script.c):
 *   - OP_CHECKSIG / OP_CHECKSIGVERIFY                 -> +1 each
 *   - OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY:
 *       `accurate` true AND the immediately preceding opcode is a small
 *       int OP_1..OP_16 -> +N (that literal key count);
 *       otherwise -> +20 (the worst-case maximum).
 *   - OP_CHECKDATASIG / OP_CHECKDATASIGVERIFY         -> +1 each ONLY if
 *       SCRIPT_VERIFY_CHECKDATASIG_SIGOPS (bit 11) is set in `flags`;
 *       when that flag is clear these opcodes count as ZERO sigops.
 * Parsing stops silently at the first malformed/over-long push (a partial
 * count is returned, never an error) — matching upstream.
 *
 * `accurate` only affects multisig: false always charges 20 per multisig
 * (the upper bound used where the redeem script is unknown); true reads the
 * literal key count. This is NOT a security toggle — `false` over-counts,
 * never under-counts. For a P2SH prevout use
 * script_get_sig_op_count_p2sh instead, which unwraps the redeem script. */
uint32_t script_get_sig_op_count(const struct script *s, uint32_t flags,
                                  bool accurate);

/* P2SH-aware sigop counter.  Mirrors zclassicd
 * src/script/script.cpp::CScript::GetSigOpCount(flags, scriptSig).
 *
 * If `script_pub_key` is not P2SH, or the SCRIPT_VERIFY_P2SH flag is
 * not set in `flags`, returns the accurate sigop count of
 * `script_pub_key` itself (equivalent to the fAccurate=true counter).
 *
 * For a P2SH prevout: walks `script_sig`, rejects it (returns 0) if
 * any opcode exceeds OP_16 (scriptSig must be push-only for P2SH
 * spends), then counts sigops in the last pushed payload (the
 * redeem script) with fAccurate=true.
 *
 * No per-input cap is applied here — the 15-sigop limit is policy
 * (standardness), not consensus, and is enforced at mempool
 * acceptance.  See core/modules/validation/src/sigops.c for the block-level
 * aggregate that feeds into MAX_BLOCK_SIGOPS. */
uint32_t script_get_sig_op_count_p2sh(const struct script *script_pub_key,
                                       const struct script *script_sig,
                                       uint32_t flags);

static inline bool script_is_pay_to_script_hash(const struct script *s)
{
    return s->size == 23 &&
           s->data[0] == OP_HASH160 &&
           s->data[1] == 0x14 &&
           s->data[22] == OP_EQUAL;
}

#endif

