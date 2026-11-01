/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "script/script.h"
#include "script/script_flags.h"
#include <string.h>

static const struct {
    enum opcodetype code;
    const char *name;
} script_op_names[] = {
    { OP_0, "0" },
    { OP_PUSHDATA1, "OP_PUSHDATA1" },
    { OP_PUSHDATA2, "OP_PUSHDATA2" },
    { OP_PUSHDATA4, "OP_PUSHDATA4" },
    { OP_1NEGATE, "-1" },
    { OP_RESERVED, "OP_RESERVED" },
    { OP_1, "1" }, { OP_2, "2" }, { OP_3, "3" },
    { OP_4, "4" }, { OP_5, "5" }, { OP_6, "6" },
    { OP_7, "7" }, { OP_8, "8" }, { OP_9, "9" },
    { OP_10, "10" }, { OP_11, "11" }, { OP_12, "12" },
    { OP_13, "13" }, { OP_14, "14" }, { OP_15, "15" },
    { OP_16, "16" },
    { OP_NOP, "OP_NOP" }, { OP_VER, "OP_VER" },
    { OP_IF, "OP_IF" }, { OP_NOTIF, "OP_NOTIF" },
    { OP_VERIF, "OP_VERIF" }, { OP_VERNOTIF, "OP_VERNOTIF" },
    { OP_ELSE, "OP_ELSE" }, { OP_ENDIF, "OP_ENDIF" },
    { OP_VERIFY, "OP_VERIFY" }, { OP_RETURN, "OP_RETURN" },
    { OP_TOALTSTACK, "OP_TOALTSTACK" },
    { OP_FROMALTSTACK, "OP_FROMALTSTACK" },
    { OP_2DROP, "OP_2DROP" }, { OP_2DUP, "OP_2DUP" },
    { OP_3DUP, "OP_3DUP" }, { OP_2OVER, "OP_2OVER" },
    { OP_2ROT, "OP_2ROT" }, { OP_2SWAP, "OP_2SWAP" },
    { OP_IFDUP, "OP_IFDUP" }, { OP_DEPTH, "OP_DEPTH" },
    { OP_DROP, "OP_DROP" }, { OP_DUP, "OP_DUP" },
    { OP_NIP, "OP_NIP" }, { OP_OVER, "OP_OVER" },
    { OP_PICK, "OP_PICK" }, { OP_ROLL, "OP_ROLL" },
    { OP_ROT, "OP_ROT" }, { OP_SWAP, "OP_SWAP" },
    { OP_TUCK, "OP_TUCK" },
    { OP_CAT, "OP_CAT" }, { OP_SUBSTR, "OP_SUBSTR" },
    { OP_LEFT, "OP_LEFT" }, { OP_RIGHT, "OP_RIGHT" },
    { OP_SIZE, "OP_SIZE" },
    { OP_INVERT, "OP_INVERT" }, { OP_AND, "OP_AND" },
    { OP_OR, "OP_OR" }, { OP_XOR, "OP_XOR" },
    { OP_EQUAL, "OP_EQUAL" },
    { OP_EQUALVERIFY, "OP_EQUALVERIFY" },
    { OP_RESERVED1, "OP_RESERVED1" },
    { OP_RESERVED2, "OP_RESERVED2" },
    { OP_1ADD, "OP_1ADD" }, { OP_1SUB, "OP_1SUB" },
    { OP_2MUL, "OP_2MUL" }, { OP_2DIV, "OP_2DIV" },
    { OP_NEGATE, "OP_NEGATE" }, { OP_ABS, "OP_ABS" },
    { OP_NOT, "OP_NOT" },
    { OP_0NOTEQUAL, "OP_0NOTEQUAL" },
    { OP_ADD, "OP_ADD" }, { OP_SUB, "OP_SUB" },
    { OP_MUL, "OP_MUL" }, { OP_DIV, "OP_DIV" },
    { OP_MOD, "OP_MOD" },
    { OP_LSHIFT, "OP_LSHIFT" }, { OP_RSHIFT, "OP_RSHIFT" },
    { OP_BOOLAND, "OP_BOOLAND" }, { OP_BOOLOR, "OP_BOOLOR" },
    { OP_NUMEQUAL, "OP_NUMEQUAL" },
    { OP_NUMEQUALVERIFY, "OP_NUMEQUALVERIFY" },
    { OP_NUMNOTEQUAL, "OP_NUMNOTEQUAL" },
    { OP_LESSTHAN, "OP_LESSTHAN" },
    { OP_GREATERTHAN, "OP_GREATERTHAN" },
    { OP_LESSTHANOREQUAL, "OP_LESSTHANOREQUAL" },
    { OP_GREATERTHANOREQUAL, "OP_GREATERTHANOREQUAL" },
    { OP_MIN, "OP_MIN" }, { OP_MAX, "OP_MAX" },
    { OP_WITHIN, "OP_WITHIN" },
    { OP_RIPEMD160, "OP_RIPEMD160" },
    { OP_SHA1, "OP_SHA1" }, { OP_SHA256, "OP_SHA256" },
    { OP_HASH160, "OP_HASH160" }, { OP_HASH256, "OP_HASH256" },
    { OP_CODESEPARATOR, "OP_CODESEPARATOR" },
    { OP_CHECKSIG, "OP_CHECKSIG" },
    { OP_CHECKSIGVERIFY, "OP_CHECKSIGVERIFY" },
    { OP_CHECKMULTISIG, "OP_CHECKMULTISIG" },
    { OP_CHECKMULTISIGVERIFY, "OP_CHECKMULTISIGVERIFY" },
    { OP_CHECKDATASIG, "OP_CHECKDATASIG" },
    { OP_CHECKDATASIGVERIFY, "OP_CHECKDATASIGVERIFY" },
    { OP_NOP1, "OP_NOP1" }, { OP_NOP2, "OP_NOP2" },
    { OP_NOP3, "OP_NOP3" }, { OP_NOP4, "OP_NOP4" },
    { OP_NOP5, "OP_NOP5" }, { OP_NOP6, "OP_NOP6" },
    { OP_NOP7, "OP_NOP7" }, { OP_NOP8, "OP_NOP8" },
    { OP_NOP9, "OP_NOP9" }, { OP_NOP10, "OP_NOP10" },
    { OP_INVALIDOPCODE, "OP_INVALIDOPCODE" },
};

/* Spelling of opcode from script_op_names, or "OP_UNKNOWN". */
static const char *script_op_name_lookup(enum opcodetype opcode)
{
    size_t i;
    size_t n = sizeof(script_op_names) / sizeof(script_op_names[0]);

    for (i = 0; i < n; i++) {
        if (script_op_names[i].code == opcode)
            return script_op_names[i].name;
    }
    return "OP_UNKNOWN";
}

const char *script_get_op_name(enum opcodetype opcode)
{
    return script_op_name_lookup(opcode);
}

uint32_t script_get_sig_op_count(const struct script *s, uint32_t flags,
                                  bool accurate)
{
    uint32_t n = 0;
    size_t pc = 0;
    enum opcodetype last_opcode = OP_INVALIDOPCODE;

    while (pc < s->size) {
        enum opcodetype opcode;
        /* Data-less walk (data=NULL): zclassicd GetSigOpCount traverses
         * the FULL script via a payload-less GetOp (script.cpp:159-167).
         * Passing a payload buffer would stop at a >520-byte push
         * (script_get_op's destination-capacity guard) and UNDERCOUNT
         * sigops appearing after it — a MAX_BLOCK_SIGOPS fork risk,
         * since output scriptPubKeys are sigop-counted at block
         * acceptance but never executed. Only the opcode stream feeds
         * the count below. */
        if (!script_get_op(s, &pc, &opcode, NULL, NULL))
            break;

        switch (opcode) {
        case OP_CHECKSIG:
        case OP_CHECKSIGVERIFY:
            n++;
            break;
        case OP_CHECKDATASIG:
        case OP_CHECKDATASIGVERIFY:
            if (flags & (1U << 11)) /* SCRIPT_VERIFY_CHECKDATASIG_SIGOPS */
                n++;
            break;
        case OP_CHECKMULTISIG:
        case OP_CHECKMULTISIGVERIFY:
            if (accurate && last_opcode >= OP_1 && last_opcode <= OP_16)
                n += (uint32_t)(last_opcode - (OP_1 - 1));
            else
                n += 20;
            break;
        default:
            break;
        }
        last_opcode = opcode;
    }
    return n;
}

uint32_t script_get_sig_op_count_p2sh(const struct script *script_pub_key,
                                       const struct script *script_sig,
                                       uint32_t flags)
{
    /* Non-P2SH (or P2SH verification disabled): accurate count of the
     * scriptPubKey itself.  Matches zclassicd
     * src/script/script.cpp:205-207. */
    if ((flags & SCRIPT_VERIFY_P2SH) == 0 ||
        !script_is_pay_to_script_hash(script_pub_key)) {
        return script_get_sig_op_count(script_pub_key, flags, true);
    }

    /* P2SH: walk scriptSig; it must contain only push opcodes (opcode
     * <= OP_16).  Any non-push op disqualifies the whole count (return 0).
     * Remember the payload of the LAST successful push — that is the
     * redeem script.  Mirrors zclassicd src/script/script.cpp:212-223. */
    size_t pc = 0;
    unsigned char last_push[MAX_SCRIPT_ELEMENT_SIZE];
    size_t last_push_len = 0;
    while (pc < script_sig->size) {
        enum opcodetype opcode;
        unsigned char data[MAX_SCRIPT_ELEMENT_SIZE];
        size_t data_len = 0;
        if (!script_get_op(script_sig, &pc, &opcode, data, &data_len))
            return 0;
        if (opcode > OP_16)
            return 0;
        if (data_len > sizeof(last_push))
            return 0;
        memcpy(last_push, data, data_len);
        last_push_len = data_len;
    }

    /* Count sigops in the redeem script, accurate mode. */
    struct script redeem;
    script_set(&redeem, last_push, last_push_len);
    return script_get_sig_op_count(&redeem, flags, true);
}
