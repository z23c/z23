/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_rule_score — score the rules an executor was shown against the ONE
 * signal that is not a self-report: what the gate did afterwards.
 *
 * ── OFF IS SAFE. ON IS NOT. ──────────────────────────────────────────────
 *
 * This module makes two kinds of decision and applies exactly one of them.
 *
 *   RETIREMENT IS AUTOMATIC. A rule that has had its declared minimum number
 *   of runs and whose Wilson lower bound sits under its declared floor is
 *   turned off by rewriting engine/composition/rule_vocab.def in place. The
 *   unit_ids of the receipts that killed it are written into the row, so the
 *   decision is auditable by a person reading a diff and revertible by
 *   deleting one line. The worst case of a wrong retirement is that an
 *   executor stops being told something true; the gate still decides
 *   everything, and the rule can be turned back on.
 *
 *   PROMOTION IS NOT. A shadow rule that beats the obeyed baseline emits a
 *   ready-to-review PATCH and nothing else. The worst case of a wrong
 *   promotion is that every future executor is told something false, by a
 *   machine, with nobody having read it. That asymmetry is the whole safety
 *   argument of an auto-updating heuristic set: the loop may take guidance
 *   away on its own, and may only ever PROPOSE adding some.
 *
 * ── THE ONE SIGNAL ───────────────────────────────────────────────────────
 *
 * A trial is a receipt whose rules_shown carries the rule id. A pass is such
 * a receipt whose outcome.gate_pass is true. Nothing else counts: not the
 * engine's exit code, not its report, not how sensible the rule reads. That
 * is engine.h's law — the model proposes, the gate decides — applied to the
 * guidance instead of to the diff.
 *
 * A RAW PASS RATE IS NOT A SCORE. One trial and one pass is 100%, and acting
 * on it would retire good rules and promote noise. Every decision here uses
 * the WILSON LOWER BOUND at 95%, in integer arithmetic, in per-mille, so that
 * a rule with few trials scores low because little is known about it rather
 * than because it did badly. Integer arithmetic is not a style preference: a
 * scoring that has to be reproducible on another machine cannot depend on
 * floating point rounding, and this one is byte-identical for identical input
 * by construction.
 *
 * ── WHAT THIS MODULE DOES NOT DO ─────────────────────────────────────────
 *
 * It runs no process. engine.h's module contract is that this is pure logic
 * linked into the node, and a process spawn here would put a fork/exec entry
 * point into node objects for the sake of developer tooling. The scorer reads
 * and writes local files at a thin seam at the bottom of the .c and does
 * nothing else to the world.
 *
 * A SCORE GRANTS NOTHING. It changes what an executor is TOLD. It never
 * changes what an executor is ALLOWED to do; metaverse_grant_check() remains
 * the only answer to that.
 */

#ifndef ZCL_ENGINE_RULE_SCORE_H
#define ZCL_ENGINE_RULE_SCORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bounds. Every one is a refusal point: a chainlog is developer-local state
 * but it is still input, and an input with no ceiling is a denial of service
 * waiting for a bad append. */
#define ZCL_RULE_ID_MAX          72u
#define ZCL_RULE_TEXT_MAX        304u
#define ZCL_RULE_VOCAB_MAX       128u
#define ZCL_RULE_UNIT_ID_MAX     48u
#define ZCL_RULE_KIND_MAX        40u
#define ZCL_RULE_GROUP_MAX       64u
#define ZCL_RULE_ENGINE_MAX      32u
#define ZCL_RULE_MODEL_MAX       56u
#define ZCL_RULE_HEX_MAX         65u
#define ZCL_RULE_SHOWN_MAX       8u
#define ZCL_RULE_RECEIPT_MAX     4096u
#define ZCL_RULE_KILLER_MAX      8u
#define ZCL_RULE_KIND_ROWS_MAX   32u
#define ZCL_RULE_LINE_MAX        8192u
#define ZCL_RULE_DEF_MAX         (512u * 1024u)
#define ZCL_RULE_LOG_MAX         (16u * 1024u * 1024u)

/* The two vocabularies the ids are closed over. A row's source decides which
 * file tools/lint/check_rule_vocabulary.sh resolves its id against. */
enum zcl_rule_source {
    ZCL_RULE_SRC_GROK = 0,     /* a heading in a .grok rules markdown file */
    ZCL_RULE_SRC_PERSONA = 1   /* a PERSONA row in personas.def */
};

/* On-disk tokens in rule_vocab.def. Do not renumber: the rewriter maps these
 * back to the exact spelling in the file. */
enum zcl_rule_state {
    ZCL_RULE_SHADOW = 0,   /* measured, shown to nobody, not yet trusted */
    ZCL_RULE_OBEYED = 1,   /* pasted into executor prompts today */
    ZCL_RULE_RETIRED = 2   /* measured, found wanting, turned off */
};

/* What the scorer says should happen to a row. NOTHING here is applied except
 * RETIRE; see the asymmetry at the top of this file. */
enum zcl_rule_verdict {
    ZCL_RULE_VERDICT_UNTRIED = 0,     /* never shown; no opinion at all */
    ZCL_RULE_VERDICT_INSUFFICIENT,    /* shown, but fewer than min_trials */
    ZCL_RULE_VERDICT_HOLD,            /* enough trials, clears its floor */
    ZCL_RULE_VERDICT_RETIRE,          /* enough trials, under its floor */
    ZCL_RULE_VERDICT_PROMOTABLE,      /* shadow, beats the obeyed baseline */
    ZCL_RULE_VERDICT_ALREADY_RETIRED  /* off already; scored, never re-decided */
};

const char *zcl_rule_state_label(enum zcl_rule_state s);
const char *zcl_rule_source_label(enum zcl_rule_source s);
const char *zcl_rule_verdict_label(enum zcl_rule_verdict v);
/* The exact token this state is spelled with in rule_vocab.def. */
const char *zcl_rule_state_token(enum zcl_rule_state s);

/* ── the vocabulary ──────────────────────────────────────────────────── */

struct zcl_rule_row {
    char                 id[ZCL_RULE_ID_MAX];
    char                 text[ZCL_RULE_TEXT_MAX];
    enum zcl_rule_source source;
    enum zcl_rule_state  state;
    uint32_t             floor_permille;
    uint32_t             min_trials;
    /* 1-based line in the parsed .def, or 0 for the compiled-in table. The
     * rewriter and the promotion patch both need it, and deriving it a second
     * time from the id would be a second parser to keep in step. */
    uint32_t             line;
};

struct zcl_rule_vocab {
    struct zcl_rule_row row[ZCL_RULE_VOCAB_MAX];
    uint32_t            count;
};

/* The vocabulary compiled into this binary from engine/composition/rule_vocab.def.
 * Present so a malformed row is a BUILD failure rather than a runtime one, and
 * so a caller with no checkout still has the ids. */
const struct zcl_rule_vocab *zcl_rule_vocab_builtin(void);

/* Parse rule_vocab.def text. Returns false on a row that does not carry six
 * fields, an unknown state or source token, a duplicate id, or more rows than
 * the bound. Refusing is the point: a half-parsed vocabulary would score the
 * rows it understood and silently ignore the rest. */
bool zcl_rule_vocab_parse(const char *text, size_t len,
                          struct zcl_rule_vocab *out);

const struct zcl_rule_row *zcl_rule_vocab_find(const struct zcl_rule_vocab *v,
                                               const char *id);

/* ── the receipts ────────────────────────────────────────────────────── */

/* One zcl.engine_unit_receipt.v1 line. Integers only, as the schema says: a
 * float in a receipt is a number two readers can disagree about. */
struct zcl_rule_receipt {
    char     unit_id[ZCL_RULE_UNIT_ID_MAX];
    char     engine[ZCL_RULE_ENGINE_MAX];
    char     model[ZCL_RULE_MODEL_MAX];
    char     kind[ZCL_RULE_KIND_MAX];
    char     group[ZCL_RULE_GROUP_MAX];
    char     template_sha3[ZCL_RULE_HEX_MAX];
    char     task_sha3[ZCL_RULE_HEX_MAX];
    char     worktree_head[ZCL_RULE_HEX_MAX];
    char     rules_shown[ZCL_RULE_SHOWN_MAX][ZCL_RULE_ID_MAX];
    uint32_t rules_shown_count;
    uint64_t ts;
    uint64_t prompt_tokens;
    uint64_t completion_tokens;
    uint64_t wall_ms;
    int64_t  http_status;
    /* outcome */
    bool     applied;
    uint32_t groups_ran;
    uint32_t groups_failed;
    bool     gate_pass;
    uint32_t retries;
    uint32_t lines_changed;
    int64_t  lint_rc;
    /* position, 1-based, in the log that produced it */
    uint32_t seq;
};

struct zcl_rule_receipt_log {
    struct zcl_rule_receipt r[ZCL_RULE_RECEIPT_MAX];
    uint32_t                count;
};

/* Why a log was refused. A reader that collapsed these would send an operator
 * to repair a hash chain when the real fault was a truncated write. */
enum zcl_rule_chain_status {
    ZCL_RULE_CHAIN_OK = 0,
    ZCL_RULE_CHAIN_EMPTY,        /* no records at all */
    ZCL_RULE_CHAIN_MALFORMED,    /* a line is not a receipt of this schema */
    ZCL_RULE_CHAIN_BROKEN,       /* prev_sha3 does not match the line before */
    ZCL_RULE_CHAIN_OVERFLOW      /* more records or a longer line than bounds */
};

const char *zcl_rule_chain_status_label(enum zcl_rule_chain_status s);

/* Parse and VERIFY a chainlog. Every line's prev_sha3 must be the SHA3-256 of
 * the previous line's exact bytes, the newline excluded; the first line's must
 * be 64 zeros. A break refuses the WHOLE log rather than scoring the prefix:
 * a score computed from the honest half of a tampered ledger is a number that
 * reads as evidence and is not. `*bad_line` is the 1-based line that refused,
 * or 0. */
enum zcl_rule_chain_status
zcl_rule_receipts_parse(const char *text, size_t len,
                        struct zcl_rule_receipt_log *out, uint32_t *bad_line);

/* The chain link for one line's exact bytes, lowercase hex, NUL-terminated.
 * Exported because a fixture generator has to compute the same thing and a
 * second implementation of it would be a second thing to keep in step. */
void zcl_rule_chain_link(const char *line, size_t len,
                         char out[ZCL_RULE_HEX_MAX]);

/* ── the scores ──────────────────────────────────────────────────────── */

struct zcl_rule_score {
    char                  id[ZCL_RULE_ID_MAX];
    enum zcl_rule_state   state;
    uint32_t              trials;
    uint32_t              passes;
    uint32_t              lower_permille;      /* Wilson 95% lower bound */
    uint32_t              rate_permille;       /* the raw rate, for contrast */
    uint32_t              mean_retries_milli;  /* mean * 1000 */
    uint32_t              mean_lines_milli;    /* mean * 1000 */
    uint32_t              floor_permille;
    uint32_t              min_trials;
    enum zcl_rule_verdict verdict;
    /* The receipts that killed it, in log order, capped. Written into the row
     * comment so a retirement can be argued with. */
    char                  killer[ZCL_RULE_KILLER_MAX][ZCL_RULE_UNIT_ID_MAX];
    uint32_t              killer_count;
    uint32_t              killer_total;        /* failures seen, uncapped */
};

/* The same numbers for one template kind. A rule can look bad because the
 * TEMPLATE it rides in is bad, and a scorer that only ever reported per rule
 * would retire the rule and leave the template. */
struct zcl_rule_kind_score {
    char     kind[ZCL_RULE_KIND_MAX];
    uint32_t trials;
    uint32_t passes;
    uint32_t lower_permille;
    uint32_t rate_permille;
    uint32_t mean_retries_milli;
    uint32_t mean_lines_milli;
};

struct zcl_rule_scoring {
    struct zcl_rule_score      rule[ZCL_RULE_VOCAB_MAX];
    uint32_t                   rule_count;
    struct zcl_rule_kind_score kind[ZCL_RULE_KIND_ROWS_MAX];
    uint32_t                   kind_count;
    /* Median lower bound of the obeyed rules that have reached min_trials.
     * A shadow rule must beat this to be proposed. */
    uint32_t                   obeyed_baseline_permille;
    bool                       baseline_known;
    uint32_t                   receipts;
    uint32_t                   retire_count;
    uint32_t                   promotable_count;
};

/* Wilson lower bound at 95%, per-mille, integer arithmetic only.
 *   LB = (2k + z^2 - z*sqrt(z^2 + 4k(n-k)/n)) / (2(n + z^2)), z = 1.96
 * n == 0 is 0: nobody measured is not the same fact as it failed. */
uint32_t zcl_rule_wilson_lower_permille(uint32_t passes, uint32_t trials);

/* Score every row of `v` against `log`. Deterministic: the same vocabulary and
 * the same log produce the same struct, every field, every time. */
void zcl_rule_score_all(const struct zcl_rule_vocab *v,
                        const struct zcl_rule_receipt_log *log,
                        struct zcl_rule_scoring *out);

/* Render the scoring as bytes. Byte-identical for identical input — that is
 * the property tests/harness/src/test_engine_rules.c asserts, and the reason
 * nothing here prints a time, a path or a pointer. Returns the length written,
 * or 0 if it does not fit. */
size_t zcl_rule_report_render(const struct zcl_rule_scoring *s,
                              char *buf, size_t cap);

/* ── applying a decision ─────────────────────────────────────────────── */

/* Produce the new text of rule_vocab.def with every RETIRE verdict applied:
 * the row's state token becomes ZCL_RULE_RETIRED and an audit comment naming
 * the trials, the bound, the floor and the killing unit_ids is written on the
 * line above it. Pure — it writes no file. Returns the length, or 0 if it does
 * not fit. */
size_t zcl_rule_vocab_apply_retirements(const char *def_text, size_t def_len,
                                        const struct zcl_rule_scoring *s,
                                        char *buf, size_t cap);

/* Produce a unified diff that would promote one shadow row to obeyed, with
 * three lines of context so `git apply` and `patch` both take it. Pure. This
 * is the ONLY thing promotion ever produces; nothing applies it. */
size_t zcl_rule_promotion_patch(const char *def_text, size_t def_len,
                                 const char *def_path,
                                 const struct zcl_rule_row *row,
                                 const struct zcl_rule_score *score,
                                 uint32_t obeyed_baseline_permille,
                                 char *buf, size_t cap);

/* ── the file seam ───────────────────────────────────────────────────── */

/* Everything above is a function of its arguments. Everything below touches
 * the filesystem and nothing else — no process, no socket, no clock. */

struct zcl_rule_run {
    enum zcl_rule_chain_status chain;
    uint32_t                   bad_line;
    bool                       vocab_ok;
    bool                       log_ok;
    struct zcl_rule_scoring    scoring;
    uint32_t                   retired_written;    /* rows turned off */
    uint32_t                   patches_written;    /* promotions proposed */
    char                       note[256];
};

/* Read the vocabulary and the chainlog, score them, and — only when `apply`
 * is true — write the retirements back into `vocab_path` and one patch per
 * promotable rule into `<state_dir>/promotions/<id>.patch`.
 *
 * apply == false is a pure read and is what the `z23 code rules` leaf calls;
 * that leaf is declared READ and must stay one. */
bool zcl_rule_score_run(const char *vocab_path, const char *chainlog_path,
                        const char *state_dir, bool apply,
                        struct zcl_rule_run *out);

/* The default chainlog under a state directory, and the promotions directory.
 * One spelling of each, so a reader and a writer cannot disagree. */
#define ZCL_RULE_CHAINLOG_NAME   "engine_receipts.chainlog"
#define ZCL_RULE_PROMOTIONS_DIR  "promotions"
#define ZCL_RULE_CANDIDATES_NAME "candidates.def"

#endif /* ZCL_ENGINE_RULE_SCORE_H */
