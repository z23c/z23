/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * lib/script/src/interpreter.c — adapter layer for the pure script VM.
 *
 * The OP_* dispatch loop and the verify_script orchestrator now live
 * in domain/consensus/src/script_interp.c. This file owns:
 *   - heap-backed stack allocation helpers (stack_init / stack_free /
 *     stack_copy_active), used by callers (fuzz harness, tests, the
 *     pure verifier itself) to materialise script_stack buffers;
 *   - the public eval_script / verify_script symbols, kept as
 *     thin wrappers so every existing caller compiles unchanged.
 *
 * The split keeps allocator-side glue in lib/script while consensus
 * decisions live in the hexagonal DOMAIN layer. The domain code never
 * touches I/O, clocks, RNG, or global state — its signature-checker
 * callback (struct sig_checker) is the ONLY impure surface, and that
 * is supplied by the caller (lib/validation typically pairs it with
 * the sigcache + ECDSA verifier). */

#include "script/interpreter.h"

#include "domain/consensus/script_interp.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

bool stack_init(struct script_stack *s)
{
    s->count = 0;
    s->items = zcl_calloc(MAX_STACK_ITEMS, sizeof(*s->items), "script_stack");
    return s->items != NULL;
}

void stack_free(struct script_stack *s)
{
    if (!s) return;
    free(s->items);
    s->items = NULL;
    s->count = 0;
}

bool stack_copy_active(struct script_stack *dst,
                       const struct script_stack *src)
{
    if (!dst->items || !src->items) return false;
    if (src->count > MAX_STACK_ITEMS) return false;
    if (src->count > 0)
        memcpy(dst->items, src->items, src->count * sizeof(*src->items));
    dst->count = src->count;
    return true;
}

/* Thin forwarders to the domain implementation. The names + signatures
 * are preserved exactly so every caller (connect_block, bg_validation,
 * script_validate_stage, fuzz_script) links unchanged. */

bool eval_script(struct script_stack *stack,
                 const struct script *script,
                 unsigned int flags,
                 const struct sig_checker *checker,
                 uint32_t consensus_branch_id,
                 ScriptError *serror)
{
    return domain_consensus_eval_script(stack, script, flags, checker,
                                        consensus_branch_id, serror);
}

bool verify_script(const struct script *script_sig,
                   const struct script *script_pub_key,
                   unsigned int flags,
                   const struct sig_checker *checker,
                   uint32_t consensus_branch_id,
                   ScriptError *serror)
{
    return domain_consensus_verify_script(script_sig, script_pub_key, flags,
                                          checker, consensus_branch_id,
                                          serror);
}
