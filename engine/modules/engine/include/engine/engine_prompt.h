/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_prompt — the rules every dispatched unit must be told, and the one
 * decision about where they travel.
 *
 * WHY THIS IS NOT A STRING IN THE TOOL
 * ------------------------------------
 * An OpenAI-dialect vendor takes a system prompt as its own field; a CLI
 * vendor has no such field and reads one file. The composition lives here,
 * not in a tool, so it can be asserted (and the --dry-run preview cannot
 * diverge from what is sent). engine_prompt_compose() is the single
 * answer to "what exact bytes does a vendor of this wire receive", and
 * test_engine holds it to that for every wire in the enum.
 *
 * THE RULE
 * --------
 * A wire that carries a separate system channel gets the rules there and the
 * composed prompt alone in its prompt channel. A wire that does not gets the
 * rules inline, ahead of the prompt. Sending them twice is not harmless: a
 * model shown the same block in two places learns it is decoration.
 */

#ifndef ZCL_ENGINE_PROMPT_H
#define ZCL_ENGINE_PROMPT_H

#include "engine/engine.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* The rules a dispatched unit is held to. Stable text: it is quoted into a
 * receipt and compared across runs, so edits to it change what a receipt
 * means. */
const char *engine_system_rules(void);

/* True when this wire has a system channel of its own. The one place the
 * question is answered, so a new wire cannot be added without deciding. */
bool engine_wire_has_system_channel(enum engine_wire wire);

/* The exact bytes a vendor of `wire` must be handed as its prompt. Returns a
 * newly allocated NUL-terminated string the caller frees, and writes its
 * length (excluding the NUL) to *out_len when out_len is non-NULL. NULL on a
 * NULL prompt, on an unknown wire, or when the result would exceed
 * ENGINE_MAX_PROMPT_BYTES — an over-long prompt is refused, never truncated,
 * because a prompt cut in half still looks like a prompt. */
char *engine_prompt_compose(enum engine_wire wire, const char *prompt,
                            size_t *out_len);

/* ── the declared shape of a prompt ─────────────────────────────────── */

/* When a section must appear. See prompt_sections.def for the rows. */
enum engine_prompt_need {
    ENGINE_PROMPT_NEED_ALWAYS = 0,
    ENGINE_PROMPT_NEED_NO_SYSTEM_CHANNEL = 1,
    ENGINE_PROMPT_NEED_OPTIONAL = 2,
};

struct engine_prompt_section {
    const char *id;      /* stable name, quoted in a refusal */
    enum engine_prompt_need need;
    const char *marker;  /* exact substring that proves it is there */
};

/* The rows, in the order a reader meets them. */
size_t engine_prompt_section_count(void);
const struct engine_prompt_section *engine_prompt_section_at(size_t i);

/* What an audit of one composed prompt found. `missing` and `misplaced`
 * point at section ids owned by this module and outlive the call. */
struct engine_prompt_audit {
    size_t required;       /* sections this wire requires */
    size_t present;        /* of those, how many were found */
    const char *missing;   /* first required section not found */
    const char *misplaced; /* first required section out of order */
    const char *repeated;  /* first section a wire must NOT carry, but does */
};

/* Audit `composed` against the registry for `wire`. Returns true only
 * when every required section is present, in order, and no section the
 * wire carries elsewhere is repeated inline. Fills *out either way, so
 * a caller can name what was wrong. False on a NULL argument too — a
 * prompt nobody can read is not a prompt that passed. */
bool engine_prompt_audit_text(enum engine_wire wire, const char *composed,
                              struct engine_prompt_audit *out);

/* SHA3-256 over the ordered rows (id, need, marker). The version
 * identity of the prompt shape: two runs whose shape hashes differ did
 * not receive comparably shaped prompts, whatever else matched. */
void engine_prompt_shape_sha3(uint8_t out[32]);

/* ── prompt templates, keyed by task kind ───────────────────────────────
 *
 * The sections above say what shape a prompt has. A template says what goes
 * IN those sections for one kind of job, and the rows are in
 * engine/composition/prompt_templates.def — read its header for the
 * vocabulary rule this API enforces.
 *
 * The distinction that earned this: "make the group pass" and "write a test
 * that fails first" are contradictory instructions, and before templates
 * existed every dispatch got whichever one was hard-coded in the tool. */

/* The kinds, in declaration order. Iteration exists so `--kind ?`, the lint
 * gate and the tests all enumerate one table rather than three copies. */
size_t engine_prompt_kind_count(void);
const char *engine_prompt_kind_at(size_t i);

/* The capability floor a kind declares for the worker that runs it: light
 * kinds are read-only or mechanical, standard kinds write code. A declared
 * floor a dispatcher may exceed, not a scheduling decision. */
enum engine_prompt_tier {
    ENGINE_PROMPT_TIER_UNKNOWN = 0,
    ENGINE_PROMPT_TIER_LIGHT,
    ENGINE_PROMPT_TIER_STANDARD,
};

/* The tier `kind` declares; UNKNOWN for NULL, an unknown kind, or a kind
 * with no tier row. The tier is a floor for the worker, never a schedule. */
enum engine_prompt_tier engine_prompt_kind_tier(const char *kind);

/* What a unit of a kind is expected to PRODUCE. EDIT: it changes files in the
 * worktree (the default for a kind with no declaration). REPORT: it must
 * change nothing; its product is its reply. UNKNOWN is only for a kind that
 * does not exist. */
enum engine_prompt_effect {
    ENGINE_PROMPT_EFFECT_UNKNOWN = 0,
    ENGINE_PROMPT_EFFECT_EDIT,
    ENGINE_PROMPT_EFFECT_REPORT,
};

/* The effect `kind` declares; UNKNOWN for NULL, an empty or unknown kind
 * (the same answer engine_prompt_kind_tier gives), EDIT for a known kind with
 * no effect row. A kind that writes any file is EDIT. */
enum engine_prompt_effect engine_prompt_kind_effect(const char *kind);

/* True when the tier rows and the template kinds agree both ways: every tier
 * row names a kind that has template rows, no kind has two tier rows, and
 * every template kind has one. Every effect row names a kind that has
 * template rows, and no kind has two effect rows. On false, *why_kind (when
 * non-NULL) names the first offending kind; it is NULL on true. */
bool engine_prompt_tiers_closed(const char **why_kind);

/* "unknown", "light" or "standard". */
const char *engine_prompt_tier_name(enum engine_prompt_tier tier);

/* The body this kind supplies for this section, or NULL when it supplies
 * none. Both arguments are matched exactly; an unknown kind or section is
 * NULL, never a fallback to another kind's words. */
const char *engine_prompt_template_body(const char *kind,
                                        const char *section_id);

/* True when `kind` is declared AND supplies a non-empty body for every
 * section prompt_sections.def marks ENGINE_PROMPT_NEED_ALWAYS.
 *
 * This is what "selectable" means. A kind missing a required body, or
 * supplying `""`, would compose a prompt whose section is a bare header,
 * which the audit cannot catch — the marker is present, the guidance is
 * not — so the refusal happens here, before dispatch, and the lint gate
 * refuses the same row at build time so nobody meets it at run time. */
bool engine_prompt_kind_is_complete(const char *kind);

/* SHA3-256 over one kind's ordered (section, body) rows. The version
 * identity of a template: two runs whose template hashes differ were given
 * different instructions for the same named kind, and comparing their
 * outcomes as if they were the same experiment is how a heuristic learns
 * something that is not true. Writes 32 zero bytes for an unknown kind. */
void engine_prompt_template_sha3(const char *kind, uint8_t out[32]);

/* Exact preimage of template_sha3, bounded independently of dispatch text.
 * Caller frees *wire. Refusal clears both outputs; unknown or incomplete
 * kinds are refused. The address is SHA3-256 of these bytes, without a CAS
 * tag. Addressed CAS readers must independently recompute it. */
#define ENGINE_PROMPT_TEMPLATE_MAX_BYTES (64u * 1024u)
bool engine_prompt_template_serialize(const char *kind, uint8_t **wire,
                                      size_t *wire_len);

/* The kind a task file declares for itself.
 *
 * A `kind:` line in the first few lines of `task` (8; the typed-contract
 * header bound when the header carries a `contract:` line), before any blank line —
 * a header, not a word found anywhere in the prose. Returns a pointer into
 * a static buffer, or NULL when the file declares none.
 *
 * --kind still wins at the caller: an operator re-running a task as a
 * review must be able to say so without editing the task. */
const char *engine_prompt_kind_from_header(const char *task);

/* ── the typed task contract ────────────────────────────────────────────
 *
 * A task file's header (the lines before the first empty line, like `kind:`)
 * may carry a typed contract. The contract is ASSERTIONS about the task, not
 * grants: nothing here authorises anything, it only lets the dispatcher
 * refuse a task whose own explicit terms contradict each other BEFORE a
 * worker is paid to find that out. The contract lives in the task bytes, so
 * the task digest covers it byte for byte; it is never hashed as a struct.
 *
 *   contract: 1                       version line (the only version)
 *   phase: author                     the current phase           (required)
 *   actor: author                     actor responsible in it     (required)
 *   execution: source-only            or may-execute              (required)
 *   evidence: executed-pass phase=verify actor=verifier [from=predecessor]
 *   evidence: notrun-report phase=author actor=author   (1 to 4, required)
 *   output: min-bytes=N max-bytes=M   optional, one line
 *   write-scope: PATH                 optional, repeatable, at most 8
 *   must-change: PATH                 optional, repeatable, at most 8
 *   base: HEX                         optional, one: 40 or 64 lowercase hex
 *   depends: HEX                      optional, repeatable, at most 4
 *   attempt: N                        optional, 1..9, default 1
 *   predecessor: HEX                  optional, one: 40 or 64 lowercase hex
 *   kind: NAME                        accepted and ignored here (see above)
 *
 * Names (phase, actor) are [a-z0-9-], 1 to 31 bytes. Tokens are separated by
 * spaces; values are trimmed of blanks and a trailing CR. A key starts at
 * column 0.
 *
 * evidence says WHAT is required (`executed-pass`: a test or gate that was
 * actually run and passed; `notrun-report`: an honest NOTRUN statement), from
 * which PHASE and which ACTOR; the optional fourth token `from=predecessor`
 * says it is carried from the previous attempt rather than produced now.
 *
 * output: both numbers are decimal, no sign, no leading zeros, at most
 * ENGINE_CONTRACT_MAX_OUTPUT_BYTES. max-bytes must be above zero and not
 * below min-bytes.
 *
 * write-scope / must-change: repo-relative paths over [A-Za-z0-9._/-], at
 * most 191 bytes, no leading `/`, no empty, `.` or `..` segment. A trailing
 * `/` on a write-scope entry makes it a directory prefix (segment-wise:
 * `src/` covers `src/a.c`; `src/a` is the single path `src/a` and covers
 * nothing else, so `src/ab.c` is not under it). Every must-change path must
 * be covered by some write-scope entry. execution: source-only with no
 * write-scope is a read-only unit and is fine.
 *
 * A task with no `contract:` line in its header is LEGACY: untyped, not
 * checked, and never reported as qualified. Once a `contract:` line is
 * present the task is TYPED and strict: an unsupported version, a malformed
 * header line, a key this version does not know, a duplicate of any
 * non-repeatable key, a missing required key, or exceeding a bound is
 * REFUSED. A parse failure never falls back to legacy. In a typed header
 * the only lines allowed are the keys above. A header that outgrows the
 * bounds is scanned on, only for a `contract:` line; finding one makes the
 * task typed and REFUSED as over-bound, so a contract cannot hide beyond a
 * window. Line ends must be bare LF for the blank line: a CR before LF is
 * trimmed from values, but a line holding only CR is not a blank line.
 *
 * Rules (each refusal names the fields and the smallest correction):
 *   SOURCE_ONLY_EXECUTED_PASS  source-only and an executed-pass evidence
 *                              owned by the current phase and actor;
 *   duplicate evidence         same what, phase and actor listed twice;
 *   one phase, one actor       evidence in the task's phase naming another
 *                              actor than the task's;
 *   output bounds, must-change coverage, depends needs base, depends is not
 *   base and not repeated, attempt above 1 needs a predecessor and a
 *   predecessor needs attempt above 1, from=predecessor needs attempt above
 *   1, and a predecessor's executed-pass is never accepted on a repair
 *   attempt (it covers different bytes).
 *
 * DELIBERATELY NOT DECIDED: that any evidence is true or any test ran; that
 * a phase or actor exists or is the one dispatched; that a path exists, is
 * writable, or is inside the real territory; that a hex identity names a real
 * object or that predecessor is the attempt actually carried; that
 * write-scope entries do not overlap; that output limits fit the engine's own
 * response cap; anything about kind, tier or territory. */
#define ENGINE_CONTRACT_VERSION 1
#define ENGINE_CONTRACT_MAX_HEADER_BYTES 6144u
#define ENGINE_CONTRACT_MAX_HEADER_LINES 40u /* lines scanned in a header */
#define ENGINE_CONTRACT_MAX_FIELDS 36u       /* lines in a typed header */
#define ENGINE_CONTRACT_MAX_EVIDENCE 4u
#define ENGINE_CONTRACT_MAX_PATHS 8u         /* write-scope and must-change */
#define ENGINE_CONTRACT_MAX_DEPENDS 4u
#define ENGINE_CONTRACT_MAX_OUTPUT_BYTES 1048576u
#define ENGINE_CONTRACT_MAX_ATTEMPT 9u
#define ENGINE_CONTRACT_NAME_MAX 32u         /* buffer: names are <= 31 */
#define ENGINE_CONTRACT_PATH_MAX 192u        /* buffer: paths are <= 191 */
#define ENGINE_CONTRACT_HEX_MAX 65u          /* buffer: 40 or 64 hex */
#define ENGINE_CONTRACT_REASON_BYTES 448u

enum engine_contract_result {
    ENGINE_CONTRACT_LEGACY = 0, /* no `contract:` line: untyped, unchecked */
    ENGINE_CONTRACT_OK,         /* typed and self-consistent (not "proven") */
    ENGINE_CONTRACT_REFUSED,    /* typed and contradictory or malformed */
};

enum engine_contract_execution {
    ENGINE_CONTRACT_EXEC_UNSET = 0,
    ENGINE_CONTRACT_EXEC_SOURCE_ONLY,
    ENGINE_CONTRACT_EXEC_MAY_EXECUTE,
};

enum engine_contract_what {
    ENGINE_CONTRACT_EVIDENCE_EXECUTED_PASS = 0,
    ENGINE_CONTRACT_EVIDENCE_NOTRUN_REPORT,
};

struct engine_contract_evidence {
    enum engine_contract_what what;
    char phase[ENGINE_CONTRACT_NAME_MAX];
    char actor[ENGINE_CONTRACT_NAME_MAX];
    bool from_predecessor;
};

/* The parsed view. Meaningful only for ENGINE_CONTRACT_OK (it is filled as
 * far as parsing got otherwise, for diagnostics). */
struct engine_contract {
    unsigned version;
    char phase[ENGINE_CONTRACT_NAME_MAX];
    char actor[ENGINE_CONTRACT_NAME_MAX];
    enum engine_contract_execution execution;
    size_t evidence_count;
    struct engine_contract_evidence evidence[ENGINE_CONTRACT_MAX_EVIDENCE];
    bool has_output;
    unsigned min_bytes, max_bytes;
    size_t scope_count, must_count, depends_count;
    char write_scope[ENGINE_CONTRACT_MAX_PATHS][ENGINE_CONTRACT_PATH_MAX];
    char must_change[ENGINE_CONTRACT_MAX_PATHS][ENGINE_CONTRACT_PATH_MAX];
    char base[ENGINE_CONTRACT_HEX_MAX];
    char depends[ENGINE_CONTRACT_MAX_DEPENDS][ENGINE_CONTRACT_HEX_MAX];
    unsigned attempt;
    char predecessor[ENGINE_CONTRACT_HEX_MAX];
};

/* Pure, allocation-free, one bounded pass over the header of task[0..len)
 * (plus, past a bound, a scan for a `contract:` line only). `view` may be
 * NULL. A NUL byte anywhere in task[0..len) is REFUSED, typed or not, because
 * a task is text. `reason` (cap bytes, NUL-terminated) is filled on REFUSED
 * and is empty otherwise. */
enum engine_contract_result engine_contract_check(
    const char *task, size_t len, struct engine_contract *view,
    char *reason, size_t reason_cap);

#endif /* ZCL_ENGINE_PROMPT_H */
