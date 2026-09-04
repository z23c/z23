/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_state — a model's own account of a unit carried across turns.
 *
 * ── WHY THIS EXISTS ───────────────────────────────────────────────────────
 * The harness runs a unit as up to --turns attempts, and each turn used to
 * start blind: a fresh prompt, no memory of what the model just tried or why.
 * One flash unit burned 127,536 bytes of reasoning on turn one and produced
 * no answer; turn two had none of it. The ARC-AGI-3 "provider adapter"
 * harness scored well doing the opposite — it accumulates the model's own
 * reasoning across turns and lets the model compact its own history rather
 * than have the harness truncate it.
 *
 * This module is the model-neutral half of that: it does not read any
 * vendor's reasoning field (glm, glm-cli and the fixture engine have none in
 * common), so instead the prompt asks the model to end every reply with a
 * bounded, self-written `<state>` block — what it tried, what the gate said,
 * its current hypothesis, its next step — and this module extracts it,
 * independent of engine_patch.c's envelope parsing. A CLI engine that edits
 * the worktree directly and never prints file bodies still owes this block
 * in its final message; an API engine that returns an envelope owes it after
 * the envelope closes. Neither format is inspected here.
 *
 * ── WHAT LIVES HERE VS. tools/engine_unit.c ─────────────────────────────
 * Pure logic only, like the rest of engine/modules/engine: extraction, the
 * protocol text, and formatting the carried-state preamble and the
 * compaction-only prompt. The turn loop that calls these, writes
 * <state-dir>/state.txt, and reads a sibling attempt's state.txt lives in
 * tools/engine_unit.c, same split as engine_patch.c / apply_patch().
 */

#ifndef ZCL_ENGINE_STATE_H
#define ZCL_ENGINE_STATE_H

#include <stdbool.h>
#include <stddef.h>

/* What the prompt template asks for, and the cap the harness holds it to.
 * 2,048 bytes is enough for four short paragraphs and small enough that
 * carrying it forward every turn never dominates the prompt budget the way
 * an accumulating transcript would. */
#define ENGINE_STATE_MAX_BYTES 2048u

#define ENGINE_STATE_OPEN_TAG  "<state>"
#define ENGINE_STATE_CLOSE_TAG "</state>"

/* The in-band instruction every dispatch carries, regardless of vendor or
 * delivery. Stable text: it is not quoted into a receipt today, but a future
 * reader diffing two runs' prompts should be able to tell whether this
 * changed. */
const char *engine_state_protocol_text(void);

/* Extract the state block from a reply. `text`/`len` is the raw reply as the
 * vendor returned it — this runs BEFORE, and independent of, envelope
 * parsing, so it works whether or not the reply also carries a Z23-BEGIN-FILE
 * envelope.
 *
 * A model may revise itself mid-reply, so the LAST well-formed
 * <state>...</state> pair in the text wins — the same "a path named twice"
 * rule engine_patch.c applies to a file emitted more than once. An open tag
 * with no matching close (a truncated reply) is not a match and does not
 * override an earlier complete one.
 *
 * The block's content is trimmed of leading/trailing whitespace, then copied
 * into `out` — NUL-terminated, truncated to at most out_cap-1 bytes rather
 * than refused, since a state block that ran long is still worth more than
 * none — and *out_len is set to the copied length (excluding the NUL).
 *
 * Returns false and leaves `out`/`out_len` untouched when no complete block
 * is present, so a caller can tell "the model wrote nothing" apart from "the
 * model wrote an empty block". Any NULL of text/out/out_cap==0 is treated as
 * not found. */
bool engine_state_extract(const char *text, size_t len, char *out,
                           size_t out_cap, size_t *out_len);

/* Format the block prepended to the NEXT turn's prompt. `attempt_label` is
 * NULL for the plain within-run wording ("Your carried state from the
 * previous turn:"); a non-NULL, non-empty ordinal ("1", "2", ...) selects the
 * cross-attempt wording ("State from attempt 1:"), used when this run's
 * --state-dir is `.../aN` and `.../a<N-1>/state.txt` exists.
 *
 * snprintf semantics: writes at most cap-1 bytes plus a NUL and returns the
 * number of bytes the full text would need, so a caller can detect
 * truncation the usual way. A NULL or empty `state` writes nothing and
 * returns 0 — there is no carried state to announce. */
size_t engine_state_format_preamble(char *buf, size_t cap, const char *state,
                                    const char *attempt_label);

/* The one-turn, envelope-free prompt sent for a compaction turn: the carried
 * state plus the most recent gate log tail, asking for nothing but a fresh
 * <state> block. Used when the next real turn's prompt would exceed the
 * model's input budget — see engine_state_needs_compaction() below — so the
 * harness can shrink what it is carrying without dropping it. Same snprintf
 * semantics as engine_state_format_preamble(). */
size_t engine_state_compaction_prompt(char *buf, size_t cap,
                                      const char *carried_state,
                                      const char *gate_tail);

/* Would a turn's prompt, built from these pieces, need compaction before it
 * is composed? `carried_len` and `gate_tail_len` are the carried-state and
 * gate-feedback byte counts about to be prepended; `base_len` is everything
 * else the turn's prompt would otherwise contain (task, brief, template
 * bodies, protocol text); `cap` is the budget not to exceed (pass
 * ENGINE_MAX_PROMPT_BYTES). A small fixed margin is reserved so a turn that
 * lands exactly at the edge is compacted rather than composed with nothing
 * left to add a repair note to. */
bool engine_state_needs_compaction(size_t carried_len, size_t gate_tail_len,
                                   size_t base_len, size_t cap);

#endif /* ZCL_ENGINE_STATE_H */
