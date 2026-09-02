/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_rule_mine — where a NEW rule comes from: a unit that failed the gate,
 * and the same task passing later.
 *
 * ── WHY THIS SHAPE ───────────────────────────────────────────────────────
 *
 * A rule invented from nothing is prose. A rule mined here is bound to two
 * receipts and one diff: unit A was shown a task, the gate refused it; unit B
 * was shown the SAME task (same task_sha3) later and the gate passed. Whatever
 * is in `git diff A_head B_head` is, by construction, what the gate wanted.
 * The candidate points at it.
 *
 * THE CANDIDATE IS BORN SHADOW AND STAYS THERE. Mining proposes; nothing here
 * turns a candidate on. It is appended to <state-dir>/candidates.def with its
 * evidence unit_ids so a person, or a later lane that asks an engine to phrase
 * it better, starts from something checkable rather than from a guess.
 *
 * ── NO MODEL CALL, NO PROCESS ────────────────────────────────────────────
 *
 * The text is a TEMPLATE — "when <gate> fails on <group>, check <files>" —
 * filled from the receipts and the diff. No engine is asked to write it here,
 * so this lane has no vendor, no key and no network.
 *
 * And nothing here runs git. engine.h's contract for this module is pure logic
 * linked into the node, and a fork/exec entry point in a node object for the
 * sake of developer tooling is exactly the kind of widening the capability
 * tables exist to make visible. So the caller runs the bounded command that
 * zcl_rule_mine_diff_command() renders, and hands the bytes back. That also
 * makes the miner testable from a fixture with no repository at all.
 */

#ifndef ZCL_ENGINE_RULE_MINE_H
#define ZCL_ENGINE_RULE_MINE_H

#include "engine/engine_rule_score.h"

#define ZCL_RULE_MINE_PAIR_MAX   64u
#define ZCL_RULE_MINE_FILE_MAX   4u
#define ZCL_RULE_MINE_PATH_MAX   160u
#define ZCL_RULE_MINE_DIFF_LINES 200u

/* One task that the gate refused and later accepted. */
struct zcl_rule_mine_pair {
    char     task_sha3[ZCL_RULE_HEX_MAX];
    char     fail_unit[ZCL_RULE_UNIT_ID_MAX];
    char     pass_unit[ZCL_RULE_UNIT_ID_MAX];
    char     fail_head[ZCL_RULE_HEX_MAX];
    char     pass_head[ZCL_RULE_HEX_MAX];
    char     group[ZCL_RULE_GROUP_MAX];
    char     kind[ZCL_RULE_KIND_MAX];
    /* Which gate refused first. Derived from the failing receipt: a non-zero
     * lint_rc is a lint refusal, otherwise the test groups refused. Reporting
     * one as the other would send a reader to the wrong output. */
    char     gate[16];
    uint32_t fail_seq;
    uint32_t pass_seq;
};

/* Every fail->pass pair in the log, in log order: the FIRST failure of a task
 * and the FIRST later pass of that same task. Returns how many were written. */
uint32_t zcl_rule_mine_pairs(const struct zcl_rule_receipt_log *log,
                             struct zcl_rule_mine_pair *out, uint32_t cap);

/* The exact bounded command whose output zcl_rule_mine_candidate() consumes.
 * One spelling, so the thing that reads the diff and the thing that produces
 * it cannot disagree about which two commits are being compared. */
size_t zcl_rule_mine_diff_command(const struct zcl_rule_mine_pair *p,
                                  char *buf, size_t cap);

struct zcl_rule_candidate {
    char     id[ZCL_RULE_ID_MAX];
    char     text[ZCL_RULE_TEXT_MAX];
    char     files[ZCL_RULE_MINE_FILE_MAX][ZCL_RULE_MINE_PATH_MAX];
    uint32_t file_count;
    char     evidence_fail[ZCL_RULE_UNIT_ID_MAX];
    char     evidence_pass[ZCL_RULE_UNIT_ID_MAX];
    char     gate[16];
    char     group[ZCL_RULE_GROUP_MAX];
};

/* Build the candidate for one pair from at most ZCL_RULE_MINE_DIFF_LINES lines
 * of `diff`. Lines past the bound are ignored, deliberately: a candidate that
 * grew with the size of the diff would name every file in a large change and
 * point at nothing. Returns false when the diff names no file — a fix with no
 * file in it is not evidence of anything. */
bool zcl_rule_mine_candidate(const struct zcl_rule_mine_pair *p,
                             const char *diff, size_t len,
                             struct zcl_rule_candidate *out);

/* The shadow row this candidate proposes, in rule_vocab.def's own shape, with
 * its evidence in a comment above it. Deterministic. */
size_t zcl_rule_mine_render(const struct zcl_rule_candidate *c,
                            char *buf, size_t cap);

/* Append that row to `path`, creating the file with a header if it is new.
 * Appends only: a candidates file that could be rewritten could lose evidence
 * somebody had already acted on. Returns false if the id is already present. */
bool zcl_rule_mine_append(const char *path,
                          const struct zcl_rule_candidate *c);

#endif /* ZCL_ENGINE_RULE_MINE_H */
