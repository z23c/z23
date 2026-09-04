/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_state — see engine/engine_state.h for what this is and why.
 */

#include "engine/engine_state.h"

#include <stdio.h>
#include <string.h>

const char *engine_state_protocol_text(void)
{
    return
"# Carry your state forward\n"
"\n"
"End your reply — after any files or output it carries — with exactly one\n"
"block shaped like this, at most " "2048" " bytes total:\n"
"\n"
"<state>\n"
"tried: what you attempted this turn\n"
"gate: what the gate said last time, in your own words (or \"none yet\")\n"
"hypothesis: your current best guess at what is wrong or what is needed\n"
"next: the single next step you would take\n"
"</state>\n"
"\n"
"This is the ONLY thing that survives to your next turn. Everything else you\n"
"wrote — your reasoning, your scratch work — is discarded at the turn\n"
"boundary, so anything worth remembering belongs in this block, in your own\n"
"words, not copied verbatim from the task. If you write more than one such\n"
"block, the LAST one is the one that is kept. If you omit it, whatever you\n"
"wrote last turn is carried forward unchanged and this turn is recorded as\n"
"not having updated it.\n";
}

/* Trim leading/trailing ASCII whitespace in place by narrowing [*start,*end). */
static void trim_span(const char *text, size_t *start, size_t *end)
{
    while (*start < *end &&
           (text[*start] == ' ' || text[*start] == '\t' ||
            text[*start] == '\n' || text[*start] == '\r'))
        (*start)++;
    while (*end > *start &&
           (text[*end - 1] == ' ' || text[*end - 1] == '\t' ||
            text[*end - 1] == '\n' || text[*end - 1] == '\r'))
        (*end)--;
}

bool engine_state_extract(const char *text, size_t len, char *out,
                          size_t out_cap, size_t *out_len)
{
    if (!text || !out || out_cap == 0)
        return false;

    const size_t open_len = strlen(ENGINE_STATE_OPEN_TAG);
    const size_t close_len = strlen(ENGINE_STATE_CLOSE_TAG);
    bool found = false;
    size_t best_start = 0, best_end = 0;

    size_t i = 0;
    while (i + open_len <= len) {
        if (memcmp(text + i, ENGINE_STATE_OPEN_TAG, open_len) != 0) {
            i++;
            continue;
        }
        const size_t content_start = i + open_len;
        /* Find the next close tag after this open tag. A later open tag
         * before any close is not nested — it just means this open tag has
         * no matching close and is skipped, same as a truncated reply. */
        size_t j = content_start;
        bool closed = false;
        size_t content_end = content_start;
        while (j + close_len <= len) {
            if (memcmp(text + j, ENGINE_STATE_CLOSE_TAG, close_len) == 0) {
                content_end = j;
                closed = true;
                break;
            }
            j++;
        }
        if (closed) {
            best_start = content_start;
            best_end = content_end;
            found = true;
            i = j + close_len; /* keep scanning: the LAST closed block wins */
        } else {
            break; /* an unmatched open tag ends the scan */
        }
    }

    if (!found)
        return false;

    trim_span(text, &best_start, &best_end);
    size_t n = best_end - best_start;
    if (n > out_cap - 1)
        n = out_cap - 1;
    if (n > 0)
        memcpy(out, text + best_start, n);
    out[n] = '\0';
    if (out_len)
        *out_len = n;
    return true;
}

size_t engine_state_format_preamble(char *buf, size_t cap, const char *state,
                                    const char *attempt_label)
{
    if (!state || !state[0])
        return 0;
    if (attempt_label && attempt_label[0])
        return (size_t)snprintf(buf, cap,
            "# State from attempt %s\n\n"
            "A previous attempt at this same unit ended and this is the\n"
            "state it left behind. It was written by that attempt, not\n"
            "measured, and may be wrong or stale — treat it as a lead, not a\n"
            "fact.\n\n%s\n\n", attempt_label, state);
    return (size_t)snprintf(buf, cap,
        "# Your carried state from the previous turn\n\n%s\n\n", state);
}

size_t engine_state_compaction_prompt(char *buf, size_t cap,
                                      const char *carried_state,
                                      const char *gate_tail)
{
    return (size_t)snprintf(buf, cap,
        "# Compact your state\n\n"
        "Your prompt has grown past what fits in one turn. Nothing you wrote "
        "is being thrown away by the harness, but it will not all fit going "
        "forward, so it is your turn to decide what matters.\n\n"
        "# Your state so far\n\n%s\n\n"
        "# The gate's most recent output\n\n%s\n\n"
        "Write ONLY a fresh <state> block (see the format you were given "
        "earlier), at most 2048 bytes, that keeps what still matters from "
        "the above. Do not restate the task, do not propose file changes, "
        "and do not write anything outside the block.\n",
        carried_state && carried_state[0] ? carried_state : "(none yet)",
        gate_tail && gate_tail[0] ? gate_tail : "(none yet)");
}

bool engine_state_needs_compaction(size_t carried_len, size_t gate_tail_len,
                                   size_t base_len, size_t cap)
{
    /* Reserve a fixed margin so a turn that lands exactly at the edge is
     * compacted rather than composed with no room left for a repair note or
     * the closing judging text compose_prompt() still has to append. */
    const size_t margin = 8192;
    const size_t needed = carried_len + gate_tail_len + base_len + margin;
    return needed > cap;
}

bool engine_state_next_is_operator(const char *state, size_t len)
{
    if (!state || len == 0)
        return false;
    static const char key[] = "next:";
    static const size_t key_len = sizeof(key) - 1;
    static const char tag[] = "Operator";
    static const size_t tag_len = sizeof(tag) - 1;

    const char *cur = state;
    const char *end = state + len;
    while (cur < end) {
        const char *nl = memchr(cur, '\n', (size_t)(end - cur));
        const char *line_end = nl ? nl : end;
        size_t start = (size_t)(cur - state);
        size_t stop = (size_t)(line_end - state);
        trim_span(state, &start, &stop);
        const size_t n = stop - start;
        if (n >= key_len && memcmp(state + start, key, key_len) == 0) {
            size_t vs = start + key_len;
            size_t ve = stop;
            trim_span(state, &vs, &ve);
            if (ve - vs >= tag_len && memcmp(state + vs, tag, tag_len) == 0)
                return true;
        }
        cur = nl ? nl + 1 : end;
    }
    return false;
}
