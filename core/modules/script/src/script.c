/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "script/script.h"
#include "script/script_flags.h"
#include <string.h>

const char *script_get_op_name(enum opcodetype opcode)
{
    switch (opcode) {
    case OP_0: return "0";
    case OP_PUSHDATA1: return "OP_PUSHDATA1";
    case OP_PUSHDATA2: return "OP_PUSHDATA2";
    case OP_PUSHDATA4: return "OP_PUSHDATA4";
    case OP_1NEGATE: return "-1";
    case OP_RESERVED: return "OP_RESERVED";
    case OP_1: return "1"; case OP_2: return "2"; case OP_3: return "3";
    case OP_4: return "4"; case OP_5: return "5"; case OP_6: return "6";
    case OP_7: return "7"; case OP_8: return "8"; case OP_9: return "9";
    case OP_10: return "10"; case OP_11: return "11"; case OP_12: return "12";
    case OP_13: return "13"; case OP_14: return "14"; case OP_15: return "15";
    case OP_16: return "16";
    case OP_NOP: return "OP_NOP"; case OP_VER: return "OP_VER";
    case OP_IF: return "OP_IF"; case OP_NOTIF: return "OP_NOTIF";
    case OP_VERIF: return "OP_VERIF"; case OP_VERNOTIF: return "OP_VERNOTIF";
    case OP_ELSE: return "OP_ELSE"; case OP_ENDIF: return "OP_ENDIF";
    case OP_VERIFY: return "OP_VERIFY"; case OP_RETURN: return "OP_RETURN";
    case OP_TOALTSTACK: return "OP_TOALTSTACK";
    case OP_FROMALTSTACK: return "OP_FROMALTSTACK";
    case OP_2DROP: return "OP_2DROP"; case OP_2DUP: return "OP_2DUP";
    case OP_3DUP: return "OP_3DUP"; case OP_2OVER: return "OP_2OVER";
    case OP_2ROT: return "OP_2ROT"; case OP_2SWAP: return "OP_2SWAP";
    case OP_IFDUP: return "OP_IFDUP"; case OP_DEPTH: return "OP_DEPTH";
    case OP_DROP: return "OP_DROP"; case OP_DUP: return "OP_DUP";
    case OP_NIP: return "OP_NIP"; case OP_OVER: return "OP_OVER";
    case OP_PICK: return "OP_PICK"; case OP_ROLL: return "OP_ROLL";
    case OP_ROT: return "OP_ROT"; case OP_SWAP: return "OP_SWAP";
    case OP_TUCK: return "OP_TUCK";
    case OP_CAT: return "OP_CAT"; case OP_SUBSTR: return "OP_SUBSTR";
    case OP_LEFT: return "OP_LEFT"; case OP_RIGHT: return "OP_RIGHT";
    case OP_SIZE: return "OP_SIZE";
    case OP_INVERT: return "OP_INVERT"; case OP_AND: return "OP_AND";
    case OP_OR: return "OP_OR"; case OP_XOR: return "OP_XOR";
    case OP_EQUAL: return "OP_EQUAL";
    case OP_EQUALVERIFY: return "OP_EQUALVERIFY";
    case OP_RESERVED1: return "OP_RESERVED1";
    case OP_RESERVED2: return "OP_RESERVED2";
    case OP_1ADD: return "OP_1ADD"; case OP_1SUB: return "OP_1SUB";
    case OP_2MUL: return "OP_2MUL"; case OP_2DIV: return "OP_2DIV";
    case OP_NEGATE: return "OP_NEGATE"; case OP_ABS: return "OP_ABS";
    case OP_NOT: return "OP_NOT";
    case OP_0NOTEQUAL: return "OP_0NOTEQUAL";
    case OP_ADD: return "OP_ADD"; case OP_SUB: return "OP_SUB";
    case OP_MUL: return "OP_MUL"; case OP_DIV: return "OP_DIV";
    case OP_MOD: return "OP_MOD";
    case OP_LSHIFT: return "OP_LSHIFT"; case OP_RSHIFT: return "OP_RSHIFT";
    case OP_BOOLAND: return "OP_BOOLAND"; case OP_BOOLOR: return "OP_BOOLOR";
    case OP_NUMEQUAL: return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY: return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL: return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN: return "OP_LESSTHAN";
    case OP_GREATERTHAN: return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL: return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL: return "OP_GREATERTHANOREQUAL";
    case OP_MIN: return "OP_MIN"; case OP_MAX: return "OP_MAX";
    case OP_WITHIN: return "OP_WITHIN";
    case OP_RIPEMD160: return "OP_RIPEMD160";
    case OP_SHA1: return "OP_SHA1"; case OP_SHA256: return "OP_SHA256";
    case OP_HASH160: return "OP_HASH160"; case OP_HASH256: return "OP_HASH256";
    case OP_CODESEPARATOR: return "OP_CODESEPARATOR";
    case OP_CHECKSIG: return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY: return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG: return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY: return "OP_CHECKMULTISIGVERIFY";
    case OP_CHECKDATASIG: return "OP_CHECKDATASIG";
    case OP_CHECKDATASIGVERIFY: return "OP_CHECKDATASIGVERIFY";
    case OP_NOP1: return "OP_NOP1"; case OP_NOP2: return "OP_NOP2";
    case OP_NOP3: return "OP_NOP3"; case OP_NOP4: return "OP_NOP4";
    case OP_NOP5: return "OP_NOP5"; case OP_NOP6: return "OP_NOP6";
    case OP_NOP7: return "OP_NOP7"; case OP_NOP8: return "OP_NOP8";
    case OP_NOP9: return "OP_NOP9"; case OP_NOP10: return "OP_NOP10";
    case OP_INVALIDOPCODE: return "OP_INVALIDOPCODE";
    default: return "OP_UNKNOWN";
    }
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
