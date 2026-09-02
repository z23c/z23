/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_prompt — the rules every dispatched unit must be told, and the one
 * decision about where they travel.
 *
 * WHY THIS IS NOT A STRING IN THE TOOL
 * ------------------------------------
 * It used to be a static in tools/engine_unit.c, and being a static is how
 * it went missing. An OpenAI-dialect vendor takes a system prompt as its own
 * field, so the rules were attached to the request body. A CLI vendor has no
 * such field — it reads one file — and nothing put the rules in that file.
 * So every CLI dispatch went out without them, and the --dry-run preview
 * printed the rules anyway, which is the worst shape a defect can have: the
 * thing you check to reassure yourself is the thing that lies. Nothing could
 * notice, because the decision lived inside a tool no test links.
 *
 * It is here so it can be asserted. engine_prompt_compose() is the single
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

/* The kind a task file declares for itself.
 *
 * A `kind:` line in the first few lines of `task`, before any blank line —
 * a header, not a word found anywhere in the prose. Returns a pointer into
 * a static buffer, or NULL when the file declares none.
 *
 * --kind still wins at the caller: an operator re-running a task as a
 * review must be able to say so without editing the task. */
const char *engine_prompt_kind_from_header(const char *task);

#endif /* ZCL_ENGINE_PROMPT_H */
