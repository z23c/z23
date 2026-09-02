/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * See engine/engine_prompt.h for why this is a module function and not a
 * string literal inside the dispatch tool.
 */

#include "engine/engine_prompt.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <string.h>

const char *engine_system_rules(void)
{
    return
"You are writing C23 for the Z23 repository. Read these before you write.\n"
"\n"
"  - C23 only. No Python, no external dependencies, no new vendored library.\n"
"  - Every allocation is checked. Use zcl_malloc(size, \"label\").\n"
/* The macro names below are deliberately written without a following
 * parenthesis. check-log-macro-return-type scans the RAW line, string
 * literals included — it cannot tell prompt text from a call site, and it is
 * right not to try, because the day a lint gate starts parsing intent is the
 * day something walks past it. */
"  - Every error return logs context. In a bool function use LOG_FAIL, which\n"
"    returns false; in an int function LOG_ERR, which returns -1; in a\n"
"    pointer function LOG_NULL, which returns NULL. They RETURN from the\n"
"    enclosing function; they are not print statements.\n"
"  - Never weaken an assertion, a threshold, a baseline, or a fail-closed\n"
"    refusal to get a green result. An honest red is the correct answer, and\n"
"    saying so is worth more than a change made to look busy.\n"
"  - A test file that exists proves nothing. A test group must be registered\n"
"    and must actually run.\n"
"  - Do not record anything in version control and do not publish anything\n"
"    to any remote. A person reads this work before either happens.\n";
}

bool engine_wire_has_system_channel(enum engine_wire wire)
{
    switch (wire) {
    case ENGINE_WIRE_OPENAI_CHAT:
        /* The request document carries a system message of its own. */
        return true;
    case ENGINE_WIRE_LOCAL_CLI:
        /* An installed agent CLI is handed one prompt file and nothing else.
         * Whatever the rules need to say has to be in that file. */
        return false;
    case ENGINE_WIRE_LOCAL_FIXTURE:
        /* A fixture sends nothing, but the file is still the archived record
         * of what a real vendor of this shape would have been given, so it
         * gets the same bytes. An archive that differs from the delivery is
         * an archive nobody can check a dispatch against. */
        return false;
    }
    /* A wire added to the enum without a case reaches here. Answering "it
     * has a system channel" would silently drop the rules for it, which is
     * the exact failure this module exists to end, so answer the other way. */
    return false;
}

char *engine_prompt_compose(enum engine_wire wire, const char *prompt,
                            size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (!prompt)
        LOG_NULL("engine", "no prompt to compose");

    const char *rules = engine_wire_has_system_channel(wire)
                            ? ""
                            : engine_system_rules();
    const char *gap = rules[0] ? "\n" : "";

    size_t rules_len = strlen(rules);
    size_t gap_len = strlen(gap);
    size_t prompt_len = strlen(prompt);
    size_t total = rules_len + gap_len + prompt_len;
    if (total > ENGINE_MAX_PROMPT_BYTES)
        LOG_NULL("engine",
                 "composed prompt is %zu bytes, over the %u-byte ceiling; "
                 "refusing rather than truncating",
                 total, (unsigned)ENGINE_MAX_PROMPT_BYTES);

    char *out = zcl_malloc(total + 1, "engine_prompt_compose");
    if (!out)
        LOG_NULL("engine", "could not allocate %zu prompt bytes", total + 1);

    memcpy(out, rules, rules_len);
    memcpy(out + rules_len, gap, gap_len);
    memcpy(out + rules_len + gap_len, prompt, prompt_len);
    out[total] = '\0';
    if (out_len)
        *out_len = total;
    return out;
}

/* ── the declared shape of a prompt ─────────────────────────────────── */

static const struct engine_prompt_section k_sections[] = {
#define ENGINE_PROMPT_SECTION(id_, need_, marker_) { #id_, need_, marker_ },
#include "engine/prompt_sections.def"
#undef ENGINE_PROMPT_SECTION
};

size_t engine_prompt_section_count(void)
{
    return sizeof(k_sections) / sizeof(k_sections[0]);
}

const struct engine_prompt_section *engine_prompt_section_at(size_t i)
{
    if (i >= engine_prompt_section_count())
        LOG_NULL("engine", "no prompt section at index %zu", i);
    return &k_sections[i];
}

/* Whether this wire requires the section inline. A NO_SYSTEM_CHANNEL row is
 * required exactly when the wire has no system channel, and forbidden when it
 * has one — the same row answers both, so the two answers cannot drift. */
static bool section_required(const struct engine_prompt_section *s,
                             enum engine_wire wire)
{
    switch (s->need) {
    case ENGINE_PROMPT_NEED_ALWAYS:
        return true;
    case ENGINE_PROMPT_NEED_NO_SYSTEM_CHANNEL:
        return !engine_wire_has_system_channel(wire);
    case ENGINE_PROMPT_NEED_OPTIONAL:
        return false;
    }
    /* A need added to the enum without a case. Requiring it is the safe
     * answer: a prompt is then refused until someone decides, which is
     * noisy, and the alternative is silently dropping a section. */
    return true;
}

/* Forbidden inline: a section this wire delivers through another channel.
 * Repeating it is not harmless — a model shown one block twice reads it as
 * decoration — so it is a refusal, not a warning. */
static bool section_forbidden(const struct engine_prompt_section *s,
                              enum engine_wire wire)
{
    return s->need == ENGINE_PROMPT_NEED_NO_SYSTEM_CHANNEL
           && engine_wire_has_system_channel(wire);
}

bool engine_prompt_audit_text(enum engine_wire wire, const char *composed,
                              struct engine_prompt_audit *out)
{
    struct engine_prompt_audit a;
    memset(&a, 0, sizeof(a));
    if (out)
        *out = a;
    if (!composed)
        LOG_FAIL("engine", "no composed prompt to audit");

    size_t n = engine_prompt_section_count();
    const char *cursor = composed;  /* required sections must be in order */
    for (size_t i = 0; i < n; i++) {
        const struct engine_prompt_section *s = &k_sections[i];
        const char *anywhere = strstr(composed, s->marker);

        if (section_forbidden(s, wire)) {
            if (anywhere && !a.repeated)
                a.repeated = s->id;
            continue;
        }
        if (!section_required(s, wire)) {
            /* An optional section that IS present still advances the cursor,
             * so a later required section placed before it is caught. */
            if (anywhere && anywhere >= cursor)
                cursor = anywhere + strlen(s->marker);
            continue;
        }

        a.required++;
        if (!anywhere) {
            if (!a.missing)
                a.missing = s->id;
            continue;
        }
        a.present++;
        const char *in_order = strstr(cursor, s->marker);
        if (!in_order) {
            /* Present in the prompt but only before where it belongs. */
            if (!a.misplaced)
                a.misplaced = s->id;
            continue;
        }
        cursor = in_order + strlen(s->marker);
    }

    if (out)
        *out = a;
    return a.missing == NULL && a.misplaced == NULL && a.repeated == NULL;
}

void engine_prompt_shape_sha3(uint8_t out[32])
{
    if (!out)
        return;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    size_t n = engine_prompt_section_count();
    /* Length-prefixed so two adjacent fields cannot be re-cut into the same
     * byte stream by a rename. The count leads for the same reason. */
    uint8_t hdr[4];
    zcl_write_u32_be(hdr, (uint32_t)n);
    sha3_256_write(&ctx, hdr, sizeof(hdr));
    for (size_t i = 0; i < n; i++) {
        const struct engine_prompt_section *s = &k_sections[i];
        uint8_t need = (uint8_t)s->need;
        size_t id_len = strlen(s->id);
        size_t mk_len = strlen(s->marker);
        uint8_t lens[8];
        zcl_write_u32_be(lens, (uint32_t)id_len);
        zcl_write_u32_be(lens + 4, (uint32_t)mk_len);
        sha3_256_write(&ctx, lens, sizeof(lens));
        sha3_256_write(&ctx, &need, 1);
        sha3_256_write(&ctx, (const uint8_t *)s->id, id_len);
        sha3_256_write(&ctx, (const uint8_t *)s->marker, mk_len);
    }
    sha3_256_finalize(&ctx, out);
}

/* ── prompt templates, keyed by task kind ──────────────────────────────────
 *
 * The rows live in engine/composition/prompt_templates.def and its header
 * carries the vocabulary rule. This is the lookup, and it is deliberately
 * exact-match only: falling back to another kind's words when a body is
 * missing would compose a prompt for a job nobody asked about, which is the
 * defect templates exist to end. */

struct engine_prompt_template_row {
    const char *kind;
    const char *section;
    const char *body;
};

static const struct engine_prompt_template_row k_templates[] = {
#define ENGINE_PROMPT_TEMPLATE(kind_, section_, body_) \
    { #kind_, #section_, body_ },
#include "../../../composition/prompt_templates.def"
#undef ENGINE_PROMPT_TEMPLATE
};

static size_t template_row_count(void)
{
    return sizeof(k_templates) / sizeof(k_templates[0]);
}

size_t engine_prompt_kind_count(void)
{
    size_t kinds = 0;
    for (size_t i = 0; i < template_row_count(); i++) {
        bool seen = false;
        for (size_t j = 0; j < i && !seen; j++)
            seen = strcmp(k_templates[i].kind, k_templates[j].kind) == 0;
        if (!seen)
            kinds++;
    }
    return kinds;
}

const char *engine_prompt_kind_at(size_t index)
{
    size_t kinds = 0;
    for (size_t i = 0; i < template_row_count(); i++) {
        bool seen = false;
        for (size_t j = 0; j < i && !seen; j++)
            seen = strcmp(k_templates[i].kind, k_templates[j].kind) == 0;
        if (seen)
            continue;
        if (kinds == index)
            return k_templates[i].kind;
        kinds++;
    }
    return NULL;
}

const char *engine_prompt_template_body(const char *kind,
                                        const char *section_id)
{
    if (!kind || !kind[0] || !section_id || !section_id[0])
        return NULL;
    for (size_t i = 0; i < template_row_count(); i++) {
        if (strcmp(k_templates[i].kind, kind) == 0
            && strcmp(k_templates[i].section, section_id) == 0)
            return k_templates[i].body;
    }
    return NULL;
}

bool engine_prompt_kind_is_complete(const char *kind)
{
    if (!kind || !kind[0])
        return false;
    bool declared = false;
    for (size_t i = 0; i < template_row_count() && !declared; i++)
        declared = strcmp(k_templates[i].kind, kind) == 0;
    if (!declared)
        LOG_FAIL("engine", "no prompt template declares the kind '%s'", kind);
    for (size_t i = 0; i < engine_prompt_section_count(); i++) {
        const struct engine_prompt_section *s = &k_sections[i];
        if (s->need != ENGINE_PROMPT_NEED_ALWAYS)
            continue;
        if (!engine_prompt_template_body(kind, s->id))
            LOG_FAIL("engine",
                     "the '%s' template supplies no body for the required "
                     "'%s' section, so the section would be a bare header the "
                     "audit cannot tell from a filled one", kind, s->id);
    }
    return true;
}

void engine_prompt_template_sha3(const char *kind, uint8_t out[32])
{
    if (!out)
        return;
    memset(out, 0, 32);
    if (!kind || !kind[0])
        return;
    size_t rows = 0;
    for (size_t i = 0; i < template_row_count(); i++)
        if (strcmp(k_templates[i].kind, kind) == 0)
            rows++;
    if (rows == 0)
        return;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    /* Same length-prefixed framing as the shape hash: two adjacent fields
     * must not be re-cuttable into one byte stream by a rename. */
    uint8_t hdr[4];
    zcl_write_u32_be(hdr, (uint32_t)rows);
    sha3_256_write(&ctx, hdr, sizeof(hdr));
    for (size_t i = 0; i < template_row_count(); i++) {
        if (strcmp(k_templates[i].kind, kind) != 0)
            continue;
        const size_t sn = strlen(k_templates[i].section);
        const size_t bn = strlen(k_templates[i].body);
        uint8_t lens[8];
        zcl_write_u32_be(lens, (uint32_t)sn);
        zcl_write_u32_be(lens + 4, (uint32_t)bn);
        sha3_256_write(&ctx, lens, sizeof(lens));
        sha3_256_write(&ctx, (const uint8_t *)k_templates[i].section, sn);
        sha3_256_write(&ctx, (const uint8_t *)k_templates[i].body, bn);
    }
    sha3_256_finalize(&ctx, out);
}

const char *engine_prompt_kind_from_header(const char *task)
{
    static char kind[64];
    kind[0] = '\0';
    if (!task)
        return NULL;
    const char *p = task;
    for (int line = 0; line < 8 && *p; line++) {
        const char *eol = strchr(p, '\n');
        const size_t n = eol ? (size_t)(eol - p) : strlen(p);
        if (n == 0)
            break;                    /* the header ends at the first blank */
        if (strncmp(p, "kind:", 5) == 0) {
            const char *q = p + 5;
            while (*q == ' ' || *q == '\t')
                q++;
            size_t k = 0;
            while (q < p + n && k + 1 < sizeof(kind)
                   && ((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z')
                       || (*q >= '0' && *q <= '9') || *q == '-' || *q == '_'))
                kind[k++] = *q++;
            kind[k] = '\0';
            return kind[0] ? kind : NULL;
        }
        if (!eol)
            break;
        p = eol + 1;
    }
    return NULL;
}
