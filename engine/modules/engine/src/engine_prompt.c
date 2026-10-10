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

#include <stdarg.h>
#include <stdio.h>
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

struct engine_prompt_tier_row {
    const char *kind;
    enum engine_prompt_tier tier;
};

static const struct engine_prompt_tier_row k_tiers[] = {
#define ENGINE_PROMPT_TIER_light ENGINE_PROMPT_TIER_LIGHT
#define ENGINE_PROMPT_TIER_standard ENGINE_PROMPT_TIER_STANDARD
#define ENGINE_PROMPT_TEMPLATE(kind_, section_, body_)
#define ENGINE_PROMPT_KIND_TIER(kind_, tier_) \
    { #kind_, ENGINE_PROMPT_TIER_##tier_ },
#include "../../../composition/prompt_templates.def"
#undef ENGINE_PROMPT_KIND_TIER
#undef ENGINE_PROMPT_TIER_light
#undef ENGINE_PROMPT_TIER_standard
#undef ENGINE_PROMPT_TEMPLATE
};

static size_t template_row_count(void);

static size_t tier_row_count(void)
{
    return sizeof(k_tiers) / sizeof(k_tiers[0]);
}

static bool kind_has_templates(const char *kind)
{
    for (size_t i = 0; i < template_row_count(); i++) {
        if (strcmp(k_templates[i].kind, kind) == 0)
            return true;
    }
    return false;
}

enum engine_prompt_tier engine_prompt_kind_tier(const char *kind)
{
    if (!kind || !kind[0] || !kind_has_templates(kind))
        return ENGINE_PROMPT_TIER_UNKNOWN;
    for (size_t i = 0; i < tier_row_count(); i++) {
        if (strcmp(k_tiers[i].kind, kind) == 0)
            return k_tiers[i].tier;
    }
    return ENGINE_PROMPT_TIER_UNKNOWN;
}

struct engine_prompt_effect_row {
    const char *kind;
    enum engine_prompt_effect effect;
};

static const struct engine_prompt_effect_row k_effects[] = {
#define ENGINE_PROMPT_EFFECT_report ENGINE_PROMPT_EFFECT_REPORT
#define ENGINE_PROMPT_EFFECT_edit ENGINE_PROMPT_EFFECT_EDIT
#define ENGINE_PROMPT_TEMPLATE(kind_, section_, body_)
#define ENGINE_PROMPT_KIND_TIER(kind_, tier_)
#define ENGINE_PROMPT_KIND_EFFECT(kind_, effect_) \
    { #kind_, ENGINE_PROMPT_EFFECT_##effect_ },
#include "../../../composition/prompt_templates.def"
#undef ENGINE_PROMPT_KIND_EFFECT
#undef ENGINE_PROMPT_KIND_TIER
#undef ENGINE_PROMPT_EFFECT_report
#undef ENGINE_PROMPT_EFFECT_edit
#undef ENGINE_PROMPT_TEMPLATE
};

enum engine_prompt_effect engine_prompt_kind_effect(const char *kind)
{
    if (!kind || !kind[0] || !kind_has_templates(kind))
        return ENGINE_PROMPT_EFFECT_UNKNOWN;
    for (size_t i = 0; i < sizeof(k_effects) / sizeof(k_effects[0]); i++) {
        if (strcmp(k_effects[i].kind, kind) == 0)
            return k_effects[i].effect;
    }
    return ENGINE_PROMPT_EFFECT_EDIT;
}

static bool tier_row_is_sound(size_t i)
{
    if (!kind_has_templates(k_tiers[i].kind))
        return false;
    for (size_t j = 0; j < i; j++) {
        if (strcmp(k_tiers[i].kind, k_tiers[j].kind) == 0)
            return false;
    }
    return true;
}

static bool kind_has_tier_row(const char *kind)
{
    for (size_t i = 0; i < tier_row_count(); i++) {
        if (strcmp(k_tiers[i].kind, kind) == 0)
            return true;
    }
    return false;
}

bool engine_prompt_tiers_closed(const char **why_kind)
{
    if (why_kind)
        *why_kind = NULL;
    for (size_t i = 0; i < tier_row_count(); i++) {
        if (!tier_row_is_sound(i)) {
            if (why_kind)
                *why_kind = k_tiers[i].kind;
            return false;
        }
    }
    for (size_t i = 0; i < template_row_count(); i++) {
        if (!kind_has_tier_row(k_templates[i].kind)) {
            if (why_kind)
                *why_kind = k_templates[i].kind;
            return false;
        }
    }
    return true;
}

const char *engine_prompt_tier_name(enum engine_prompt_tier tier)
{
    switch (tier) {
    case ENGINE_PROMPT_TIER_LIGHT:
        return "light";
    case ENGINE_PROMPT_TIER_STANDARD:
        return "standard";
    case ENGINE_PROMPT_TIER_UNKNOWN:
    default:
        return "unknown";
    }
}

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
        const char *body = engine_prompt_template_body(kind, s->id);
        if (!body || !body[0])
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

static bool template_wire_size(const char *kind, size_t *bytes,
                               uint32_t *rows)
{
    *bytes = 4;
    *rows = 0;
    for (size_t i = 0; i < template_row_count(); i++) {
        if (strcmp(k_templates[i].kind, kind) != 0)
            continue;
        const size_t sn = strlen(k_templates[i].section);
        const size_t bn = strlen(k_templates[i].body);
        if (sn > ENGINE_PROMPT_TEMPLATE_MAX_BYTES - 8u ||
            bn > ENGINE_PROMPT_TEMPLATE_MAX_BYTES - 8u - sn ||
            *bytes > ENGINE_PROMPT_TEMPLATE_MAX_BYTES - 8u - sn - bn)
            LOG_FAIL("engine", "selected template exceeds its wire cap");
        *bytes += 8u + sn + bn;
        (*rows)++;
    }
    return true;
}

bool engine_prompt_template_serialize(const char *kind, uint8_t **wire,
                                      size_t *wire_len)
{
    if (wire) *wire = NULL;
    if (wire_len) *wire_len = 0;
    if (!wire || !wire_len || !kind || !kind[0])
        LOG_FAIL("engine", "template serialization requires kind and outputs");
    if (!engine_prompt_kind_is_complete(kind))
        LOG_FAIL("engine", "template serialization requires a complete kind");
    size_t bytes;
    uint32_t rows;
    if (!template_wire_size(kind, &bytes, &rows))
        LOG_FAIL("engine", "cannot size selected template wire");
    uint8_t *out = zcl_malloc(bytes, "engine_template_wire");
    if (!out)
        LOG_FAIL("engine", "cannot allocate selected template wire");
    zcl_write_u32_be(out, rows);
    size_t used = 4;
    for (size_t i = 0; i < template_row_count(); i++) {
        if (strcmp(k_templates[i].kind, kind) != 0)
            continue;
        const size_t sn = strlen(k_templates[i].section);
        const size_t bn = strlen(k_templates[i].body);
        zcl_write_u32_be(out + used, (uint32_t)sn);
        zcl_write_u32_be(out + used + 4, (uint32_t)bn);
        used += 8;
        memcpy(out + used, k_templates[i].section, sn);
        used += sn;
        memcpy(out + used, k_templates[i].body, bn);
        used += bn;
    }
    *wire = out;
    *wire_len = bytes;
    return true;
}

/* How many header lines `kind:` may sit in. 8 for every task as before; a
 * task whose header carries a `contract:` line ANYWHERE in it (the whole
 * header, to its blank line or the end of the task: the same rule the
 * contract check uses, so the two cannot disagree) gets the contract header
 * bound, because its own contract lines must not push `kind:` out of reach. */
static unsigned kind_scan_limit(const char *task)
{
    const char *p = task;
    while (*p) {
        const char *eol = strchr(p, '\n');
        const size_t n = eol ? (size_t)(eol - p) : strlen(p);
        if (n == 0)
            break;
        if (strncmp(p, "contract:", 9) == 0)
            return ENGINE_CONTRACT_MAX_HEADER_LINES;
        if (!eol)
            break;
        p = eol + 1;
    }
    return 8;
}

const char *engine_prompt_kind_from_header(const char *task)
{
    static char kind[64];
    kind[0] = '\0';
    if (!task)
        return NULL;
    const char *p = task;
    const unsigned limit = kind_scan_limit(task);
    for (unsigned line = 0; line < limit && *p; line++) {
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

/* ── the typed task contract ────────────────────────────────────────────
 *
 * See engine_prompt.h for the syntax. Everything below is pure: it splits
 * the header into at most ENGINE_CONTRACT_MAX_HEADER_LINES line spans, then
 * validates those spans. It allocates nothing. */

struct contract_line {
    const char *p;
    size_t n;
};

/* Bits in `seen`, one per single-valued key. */
enum {
    SEEN_CONTRACT = 1u << 0,
    SEEN_PHASE = 1u << 1,
    SEEN_ACTOR = 1u << 2,
    SEEN_EXECUTION = 1u << 3,
    SEEN_KIND = 1u << 4,
    SEEN_OUTPUT = 1u << 5,
    SEEN_BASE = 1u << 6,
    SEEN_ATTEMPT = 1u << 7,
    SEEN_PREDECESSOR = 1u << 8,
    SEEN_REPEATABLE = 1u << 9, /* evidence, write-scope, must-change,
                                * depends: bounded by their own caps */
};

static void contract_refuse(char *reason, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void contract_refuse(char *reason, size_t cap, const char *fmt, ...)
{
    if (!reason || cap == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(reason, cap, fmt, ap);
    va_end(ap);
}

/* From `pos` to the blank line or the end of `len`: is there a line that
 * starts `contract:`? Used only once a bound has been hit. */
static bool contract_tail_has(const char *task, size_t len, size_t pos)
{
    while (pos < len) {
        const char *nl = memchr(task + pos, '\n', len - pos);
        const size_t n = nl ? (size_t)(nl - (task + pos)) : len - pos;
        if (n == 0)
            break;
        if (n >= 9 && memcmp(task + pos, "contract:", 9) == 0)
            return true;
        if (!nl)
            break;
        pos += n + 1;
    }
    return false;
}

/* Split the header (up to the first empty line) into spans. Sets *typed when
 * a `contract:` line is in the header (past a bound too: the rest of the
 * header is then scanned for that line alone) and *over when a bound was hit
 * before the header ended. Returns the span count. */
static size_t contract_split(const char *task, size_t len,
                             struct contract_line *ln, bool *typed, bool *over)
{
    size_t pos = 0, count = 0, bytes = 0;
    *typed = false;
    *over = false;
    while (pos < len) {
        const char *nl = memchr(task + pos, '\n', len - pos);
        const size_t n = nl ? (size_t)(nl - (task + pos)) : len - pos;
        if (n == 0)
            break;                         /* the header ends at the blank */
        bytes += n + 1;
        if (count == ENGINE_CONTRACT_MAX_HEADER_LINES
            || bytes > ENGINE_CONTRACT_MAX_HEADER_BYTES) {
            *over = true;
            *typed = *typed || contract_tail_has(task, len, pos);
            break;
        }
        ln[count].p = task + pos;
        ln[count].n = n;
        if (n >= 9 && memcmp(task + pos, "contract:", 9) == 0)
            *typed = true;
        count++;
        if (!nl)
            break;
        pos += n + 1;
    }
    return count;
}

static bool contract_name_ok(const char *s, size_t n)
{
    if (n == 0 || n >= ENGINE_CONTRACT_NAME_MAX)
        return false;
    for (size_t i = 0; i < n; i++) {
        const char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return false;
    }
    return true;
}

static bool contract_copy_name(char *dst, const char *s, size_t n)
{
    if (!contract_name_ok(s, n))
        return false;
    memcpy(dst, s, n);
    dst[n] = '\0';
    return true;
}

/* Next space-separated token of [*p, end); advances *p. */
static size_t contract_token(const char **p, const char *end, const char **tok)
{
    while (*p < end && **p == ' ')
        (*p)++;
    *tok = *p;
    while (*p < end && **p != ' ')
        (*p)++;
    return (size_t)(*p - *tok);
}

/* `key=NAME` where the token must start with `key` and `=`. */
static bool contract_keyed_name(const char *tok, size_t n, const char *key,
                                char *dst)
{
    const size_t kl = strlen(key);
    return n > kl + 1 && memcmp(tok, key, kl) == 0 && tok[kl] == '='
           && contract_copy_name(dst, tok + kl + 1, n - kl - 1);
}

/* Decimal, no sign, no leading zeros, at most the output cap. */
static bool contract_uint(const char *s, size_t n, unsigned *out)
{
    if (n == 0 || n > 7 || (n > 1 && s[0] == '0'))
        return false;
    unsigned v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10u + (unsigned)(s[i] - '0');
    }
    if (v > ENGINE_CONTRACT_MAX_OUTPUT_BYTES)
        return false;
    *out = v;
    return true;
}

static bool contract_keyed_uint(const char *tok, size_t n, const char *key,
                                unsigned *out)
{
    const size_t kl = strlen(key);
    return n > kl + 1 && memcmp(tok, key, kl) == 0 && tok[kl] == '='
           && contract_uint(tok + kl + 1, n - kl - 1, out);
}

static bool contract_hex_ok(const char *s, size_t n)
{
    if (n != 40 && n != 64)
        return false;
    for (size_t i = 0; i < n; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    }
    return true;
}

static bool contract_path_char_ok(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

/* One segment: not empty, not "." and not "..". */
static bool contract_seg_ok(const char *seg, size_t n)
{
    if (n == 0)
        return false;
    if (n == 1 && seg[0] == '.')
        return false;
    return !(n == 2 && seg[0] == '.' && seg[1] == '.');
}

/* A repo-relative path: [A-Za-z0-9._/-], at most 191 bytes, no leading '/',
 * no empty, "." or ".." segment. `dir_ok` lets one trailing '/' through. */
static bool contract_path_ok(const char *s, size_t n, bool dir_ok)
{
    if (n == 0 || n >= ENGINE_CONTRACT_PATH_MAX || s[0] == '/')
        return false;
    if (dir_ok && s[n - 1] == '/')
        n--;
    size_t start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i < n && s[i] != '/') {
            if (!contract_path_char_ok(s[i]))
                return false;
            continue;
        }
        if (!contract_seg_ok(s + start, i - start))
            return false;
        start = i + 1;
    }
    return true;
}

/* `executed-pass` or `notrun-report` (the whole token). */
static bool contract_parse_what(const char *tok, size_t tn,
                                enum engine_contract_what *out)
{
    if (tn == 13 && memcmp(tok, "executed-pass", 13) == 0)
        *out = ENGINE_CONTRACT_EVIDENCE_EXECUTED_PASS;
    else if (tn == 13 && memcmp(tok, "notrun-report", 13) == 0)
        *out = ENGINE_CONTRACT_EVIDENCE_NOTRUN_REPORT;
    else
        return false;
    return true;
}

/* `WHAT phase=P actor=A [from=predecessor]`. */
static bool contract_parse_evidence(const char *v, size_t n,
                                    struct engine_contract_evidence *ev)
{
    const char *p = v, *end = v + n, *tok;
    size_t tn = contract_token(&p, end, &tok);
    memset(ev, 0, sizeof(*ev));
    if (!contract_parse_what(tok, tn, &ev->what))
        return false;
    tn = contract_token(&p, end, &tok);
    if (!contract_keyed_name(tok, tn, "phase", ev->phase))
        return false;
    tn = contract_token(&p, end, &tok);
    if (!contract_keyed_name(tok, tn, "actor", ev->actor))
        return false;
    tn = contract_token(&p, end, &tok);
    if (tn == 16 && memcmp(tok, "from=predecessor", 16) == 0) {
        ev->from_predecessor = true;
        tn = contract_token(&p, end, &tok);
    }
    return tn == 0;
}

static bool contract_parse_execution(const char *v, size_t n,
                                     enum engine_contract_execution *out)
{
    if (n == 11 && memcmp(v, "source-only", 11) == 0)
        *out = ENGINE_CONTRACT_EXEC_SOURCE_ONLY;
    else if (n == 11 && memcmp(v, "may-execute", 11) == 0)
        *out = ENGINE_CONTRACT_EXEC_MAY_EXECUTE;
    else
        return false;
    return true;
}

/* ── one handler per key: fill the view or put a complaint in msg ─────── */

typedef bool (*contract_handler)(struct engine_contract *c, const char *v,
                                 size_t vn, char *msg, size_t cap);

static bool h_contract(struct engine_contract *c, const char *v, size_t vn,
                       char *msg, size_t cap)
{
    if (vn != 1 || v[0] != '0' + ENGINE_CONTRACT_VERSION) {
        contract_refuse(msg, cap, "unsupported contract version (this build "
                                  "supports 1)");
        return false;
    }
    c->version = ENGINE_CONTRACT_VERSION;
    return true;
}

static bool h_phase(struct engine_contract *c, const char *v, size_t vn,
                    char *msg, size_t cap)
{
    if (contract_copy_name(c->phase, v, vn))
        return true;
    contract_refuse(msg, cap, "bad phase name (a-z 0-9 -, 1 to 31 bytes)");
    return false;
}

static bool h_actor(struct engine_contract *c, const char *v, size_t vn,
                    char *msg, size_t cap)
{
    if (contract_copy_name(c->actor, v, vn))
        return true;
    contract_refuse(msg, cap, "bad actor name (a-z 0-9 -, 1 to 31 bytes)");
    return false;
}

static bool h_execution(struct engine_contract *c, const char *v, size_t vn,
                        char *msg, size_t cap)
{
    if (contract_parse_execution(v, vn, &c->execution))
        return true;
    contract_refuse(msg, cap, "execution must be source-only or may-execute");
    return false;
}

static bool h_kind(struct engine_contract *c, const char *v, size_t vn,
                   char *msg, size_t cap)
{
    (void)c; (void)v; (void)vn; (void)msg; (void)cap;
    return true;   /* kind: detection is engine_prompt_kind_from_header */
}

static bool contract_evidence_listed(const struct engine_contract *c,
                                     const struct engine_contract_evidence *e)
{
    for (size_t i = 0; i < c->evidence_count; i++) {
        const struct engine_contract_evidence *o = &c->evidence[i];
        if (o->what == e->what && strcmp(o->phase, e->phase) == 0
            && strcmp(o->actor, e->actor) == 0)
            return true;
    }
    return false;
}

static bool h_evidence(struct engine_contract *c, const char *v, size_t vn,
                       char *msg, size_t cap)
{
    struct engine_contract_evidence *e = &c->evidence[c->evidence_count];
    if (c->evidence_count >= ENGINE_CONTRACT_MAX_EVIDENCE) {
        contract_refuse(msg, cap, "too many evidence items (at most %u)",
                        ENGINE_CONTRACT_MAX_EVIDENCE);
        return false;
    }
    if (!contract_parse_evidence(v, vn, e)) {
        contract_refuse(msg, cap, "evidence must be `executed-pass|"
                        "notrun-report phase=NAME actor=NAME "
                        "[from=predecessor]`");
        return false;
    }
    if (contract_evidence_listed(c, e)) {
        contract_refuse(msg, cap, "duplicate evidence (this item, phase and "
                        "actor is already listed; drop one)");
        return false;
    }
    c->evidence_count++;
    return true;
}

static bool h_output(struct engine_contract *c, const char *v, size_t vn,
                     char *msg, size_t cap)
{
    const char *p = v, *end = v + vn, *tok;
    size_t tn = contract_token(&p, end, &tok);
    unsigned lo = 0, hi = 0;
    bool ok = contract_keyed_uint(tok, tn, "min-bytes", &lo);
    tn = contract_token(&p, end, &tok);
    ok = ok && contract_keyed_uint(tok, tn, "max-bytes", &hi);
    ok = ok && contract_token(&p, end, &tok) == 0;
    if (!ok) {
        contract_refuse(msg, cap, "output must be `min-bytes=N max-bytes=M` "
                        "(decimal, no sign, no leading zeros, each at most "
                        "%u)", ENGINE_CONTRACT_MAX_OUTPUT_BYTES);
        return false;
    }
    if (hi == 0 || lo > hi) {
        contract_refuse(msg, cap, "output min-bytes=%u max-bytes=%u cannot be "
                        "met (max-bytes must be above zero and not below "
                        "min-bytes); lower min-bytes or raise max-bytes",
                        lo, hi);
        return false;
    }
    c->has_output = true;
    c->min_bytes = lo;
    c->max_bytes = hi;
    return true;
}

static bool contract_add_path(char (*arr)[ENGINE_CONTRACT_PATH_MAX],
                              size_t *count, const char *key, bool dir_ok,
                              const char *v, size_t vn, char *msg, size_t cap)
{
    if (*count >= ENGINE_CONTRACT_MAX_PATHS) {
        contract_refuse(msg, cap, "too many %s entries (at most %u)", key,
                        ENGINE_CONTRACT_MAX_PATHS);
        return false;
    }
    if (!contract_path_ok(v, vn, dir_ok)) {
        contract_refuse(msg, cap, "bad %s path (repo-relative, [A-Za-z0-9._/-]"
                        ", at most 191 bytes, no leading /, no empty or . or "
                        ".. segment%s)", key,
                        dir_ok ? "; one trailing / marks a directory" : "");
        return false;
    }
    memcpy(arr[*count], v, vn);
    arr[*count][vn] = '\0';
    (*count)++;
    return true;
}

static bool h_scope(struct engine_contract *c, const char *v, size_t vn,
                    char *msg, size_t cap)
{
    return contract_add_path(c->write_scope, &c->scope_count, "write-scope",
                             true, v, vn, msg, cap);
}

static bool h_must(struct engine_contract *c, const char *v, size_t vn,
                   char *msg, size_t cap)
{
    return contract_add_path(c->must_change, &c->must_count, "must-change",
                             false, v, vn, msg, cap);
}

static bool contract_copy_hex(char *dst, const char *v, size_t vn, char *msg,
                              size_t cap, const char *key)
{
    if (!contract_hex_ok(v, vn)) {
        contract_refuse(msg, cap, "%s must be 40 or 64 lowercase hex digits",
                        key);
        return false;
    }
    memcpy(dst, v, vn);
    dst[vn] = '\0';
    return true;
}

static bool h_base(struct engine_contract *c, const char *v, size_t vn,
                   char *msg, size_t cap)
{
    return contract_copy_hex(c->base, v, vn, msg, cap, "base");
}

static bool h_predecessor(struct engine_contract *c, const char *v, size_t vn,
                          char *msg, size_t cap)
{
    return contract_copy_hex(c->predecessor, v, vn, msg, cap, "predecessor");
}

static bool h_depends(struct engine_contract *c, const char *v, size_t vn,
                      char *msg, size_t cap)
{
    if (c->depends_count >= ENGINE_CONTRACT_MAX_DEPENDS) {
        contract_refuse(msg, cap, "too many depends entries (at most %u)",
                        ENGINE_CONTRACT_MAX_DEPENDS);
        return false;
    }
    if (!contract_copy_hex(c->depends[c->depends_count], v, vn, msg, cap,
                           "depends"))
        return false;
    c->depends_count++;
    return true;
}

static bool h_attempt(struct engine_contract *c, const char *v, size_t vn,
                      char *msg, size_t cap)
{
    if (vn != 1 || v[0] < '1' || v[0] > (char)('0' + (int)ENGINE_CONTRACT_MAX_ATTEMPT)) {
        contract_refuse(msg, cap, "attempt must be one digit, 1 to %u",
                        ENGINE_CONTRACT_MAX_ATTEMPT);
        return false;
    }
    c->attempt = (unsigned)(v[0] - '0');
    return true;
}

/* Named once so an unknown key's refusal lists the table's real contents. */
#define CONTRACT_ALLOWED_KEYS "contract, kind, phase, actor, execution, " \
    "evidence, output, write-scope, must-change, base, depends, attempt, " \
    "predecessor"

static const struct contract_key {
    const char *name;
    unsigned bit;
    contract_handler fn;
} contract_keys[] = {
    {"contract", SEEN_CONTRACT, h_contract},
    {"phase", SEEN_PHASE, h_phase},
    {"actor", SEEN_ACTOR, h_actor},
    {"execution", SEEN_EXECUTION, h_execution},
    {"kind", SEEN_KIND, h_kind},
    {"evidence", SEEN_REPEATABLE, h_evidence},
    {"output", SEEN_OUTPUT, h_output},
    {"write-scope", SEEN_REPEATABLE, h_scope},
    {"must-change", SEEN_REPEATABLE, h_must},
    {"base", SEEN_BASE, h_base},
    {"depends", SEEN_REPEATABLE, h_depends},
    {"attempt", SEEN_ATTEMPT, h_attempt},
    {"predecessor", SEEN_PREDECESSOR, h_predecessor},
};

/* One `key: value` line. true when fine, else msg holds the complaint. */
static bool contract_apply(struct engine_contract *c, unsigned *seen,
                           const char *key, size_t kn, const char *v,
                           size_t vn, char *msg, size_t cap)
{
    for (size_t i = 0; i < sizeof(contract_keys) / sizeof(contract_keys[0]);
         i++) {
        const struct contract_key *k = &contract_keys[i];
        if (strlen(k->name) != kn || memcmp(k->name, key, kn) != 0)
            continue;
        if (k->bit != SEEN_REPEATABLE && (*seen & k->bit)) {
            contract_refuse(msg, cap, "duplicate key (this key may appear "
                            "once; drop the repeat)");
            return false;
        }
        *seen |= k->bit;
        return k->fn(c, v, vn, msg, cap);
    }
    contract_refuse(msg, cap, "unknown contract key; allowed keys are "
                    CONTRACT_ALLOWED_KEYS);
    return false;
}

/* True when `key` (kn bytes) is one of the contract_keys names. */
static bool contract_key_known(const char *key, size_t kn)
{
    for (size_t i = 0; i < sizeof(contract_keys) / sizeof(contract_keys[0]);
         i++) {
        if (strlen(contract_keys[i].name) == kn
            && memcmp(contract_keys[i].name, key, kn) == 0)
            return true;
    }
    return false;
}

/* Length of the `key` in `key:...` (lowercase letters and '-'), or 0 when the
 * line is not of that shape. A key over 16 bytes is not a key: the line is
 * then refused as not `key: value`, which echoes nothing from the task. */
static size_t contract_key_len(const struct contract_line *l)
{
    size_t kn = 0;
    while (kn < l->n && ((l->p[kn] >= 'a' && l->p[kn] <= 'z')
                         || l->p[kn] == '-'))
        kn++;
    return (kn == 0 || kn > 16 || kn >= l->n || l->p[kn] != ':') ? 0 : kn;
}

/* The value after `key:`, trimmed of blanks and a trailing CR. */
static size_t contract_value(const struct contract_line *l, size_t kn,
                             const char **v)
{
    const char *s = l->p + kn + 1, *end = l->p + l->n;
    while (s < end && (*s == ' ' || *s == '\t'))
        s++;
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'))
        end--;
    *v = s;
    return (size_t)(end - s);
}

/* Split `key: value` and apply it. */
static bool contract_line_apply(struct engine_contract *c, unsigned *seen,
                                const struct contract_line *l, size_t no,
                                char *reason, size_t cap)
{
    const size_t kn = contract_key_len(l);
    if (kn == 0) {
        contract_refuse(reason, cap,
                        "contract refused: header line %zu is not `key: "
                        "value` (a typed task header holds only contract "
                        "keys and kind)", no);
        return false;
    }
    if (!contract_key_known(l->p, kn)) {
        contract_refuse(reason, cap, "contract refused: header line %zu: "
                        "unknown contract key; allowed keys are "
                        CONTRACT_ALLOWED_KEYS, no);
        return false;
    }
    const char *v;
    char msg[256];
    const size_t vn = contract_value(l, kn, &v);
    msg[0] = '\0';
    bool ok = false;
    if (vn == 0)
        contract_refuse(msg, sizeof(msg), "empty value");
    else
        ok = contract_apply(c, seen, l->p, kn, v, vn, msg, sizeof(msg));
    if (!ok)
        contract_refuse(reason, cap, "contract refused: header line %zu "
                        "(`%.*s:`): %s", no, (int)kn, l->p, msg);
    return ok;
}

/* ── cross-field rules, after every line parsed ─────────────────────── */

static bool contract_rule_source_only_executed_pass(
    const struct engine_contract *c, char *reason, size_t cap)
{
    if (c->execution != ENGINE_CONTRACT_EXEC_SOURCE_ONLY)
        return true;
    for (size_t i = 0; i < c->evidence_count; i++) {
        const struct engine_contract_evidence *e = &c->evidence[i];
        if (e->what == ENGINE_CONTRACT_EVIDENCE_EXECUTED_PASS
            && strcmp(e->phase, c->phase) == 0
            && strcmp(e->actor, c->actor) == 0) {
            contract_refuse(reason, cap,
                "contract refused: execution=source-only but this same "
                "actor=%s in phase=%s owes an executed-pass; "
                "either set execution: may-execute, or move the "
                "executed-pass to a separate phase and require "
                "notrun-report here", c->actor, c->phase);
            return false;
        }
    }
    return true;
}

static bool contract_required_present(unsigned seen,
                                      const struct engine_contract *c,
                                      char *reason, size_t cap)
{
    const char *missing = !(seen & SEEN_PHASE) ? "phase"
                          : !(seen & SEEN_ACTOR) ? "actor"
                          : !(seen & SEEN_EXECUTION) ? "execution"
                          : c->evidence_count == 0 ? "evidence" : NULL;
    if (missing)
        contract_refuse(reason, cap,
                        "contract refused: required key `%s` is missing "
                        "from the typed header", missing);
    return missing == NULL;
}

/* Per evidence item: carried-from-predecessor rules and one-phase-one-actor. */
static bool contract_rule_evidence_items(const struct engine_contract *c,
                                         char *reason, size_t cap)
{
    for (size_t i = 0; i < c->evidence_count; i++) {
        const struct engine_contract_evidence *e = &c->evidence[i];
        if (e->from_predecessor && c->attempt == 1) {
            contract_refuse(reason, cap, "contract refused: evidence from="
                            "predecessor (phase=%s actor=%s) but attempt is "
                            "1; drop from=predecessor, or set attempt: 2 or "
                            "more with a predecessor:", e->phase, e->actor);
            return false;
        }
        if (e->from_predecessor
            && e->what == ENGINE_CONTRACT_EVIDENCE_EXECUTED_PASS) {
            contract_refuse(reason, cap, "contract refused: a predecessor's "
                            "executed-pass covers different bytes; require a "
                            "fresh executed-pass in a verification phase "
                            "(phase=%s actor=%s)", e->phase, e->actor);
            return false;
        }
        if (strcmp(e->phase, c->phase) == 0
            && strcmp(e->actor, c->actor) != 0) {
            contract_refuse(reason, cap, "contract refused: phase=%s is this "
                            "task's phase and its actor is %s, but evidence "
                            "names actor=%s; one phase has one actor here",
                            c->phase, c->actor, e->actor);
            return false;
        }
    }
    return true;
}

/* A must-change path is covered by an exact write-scope entry, or by a
 * directory entry (trailing '/') it sits under. Segment-wise: the entry's
 * '/' is part of the prefix, so `src/a` never covers `src/ab.c`. */
static bool contract_path_covered(const char *scope, const char *path)
{
    const size_t sl = strlen(scope);
    if (sl > 0 && scope[sl - 1] == '/')
        return strncmp(path, scope, sl) == 0;
    return strcmp(path, scope) == 0;
}

static bool contract_rule_scope(const struct engine_contract *c, char *reason,
                                size_t cap)
{
    for (size_t i = 0; i < c->must_count; i++) {
        bool covered = false;
        for (size_t j = 0; j < c->scope_count && !covered; j++)
            covered = contract_path_covered(c->write_scope[j],
                                            c->must_change[i]);
        if (!covered) {
            contract_refuse(reason, cap, "contract refused: must-change path "
                            "%s is covered by no write-scope entry; add it "
                            "to write-scope or drop the must-change",
                            c->must_change[i]);
            return false;
        }
    }
    return true;
}

static bool contract_rule_refs(const struct engine_contract *c, char *reason,
                               size_t cap)
{
    if (c->depends_count > 0 && c->base[0] == '\0') {
        contract_refuse(reason, cap, "contract refused: a dependency ref "
                        "needs the base it is relative to: add base:");
        return false;
    }
    for (size_t i = 0; i < c->depends_count; i++) {
        bool dup = strcmp(c->depends[i], c->base) == 0;
        for (size_t j = 0; j < i && !dup; j++)
            dup = strcmp(c->depends[i], c->depends[j]) == 0;
        if (dup) {
            contract_refuse(reason, cap, "contract refused: depends %s is the "
                            "base itself or is listed twice; drop the "
                            "repeat", c->depends[i]);
            return false;
        }
    }
    return true;
}

static bool contract_rule_attempt(const struct engine_contract *c,
                                  char *reason, size_t cap)
{
    if (c->attempt > 1 && c->predecessor[0] == '\0') {
        contract_refuse(reason, cap, "contract refused: attempt=%u is a "
                        "repair attempt but no predecessor is named; add "
                        "predecessor: HEX, or set attempt: 1", c->attempt);
        return false;
    }
    if (c->attempt == 1 && c->predecessor[0] != '\0') {
        contract_refuse(reason, cap, "contract refused: predecessor is set "
                        "but attempt is 1; set attempt: 2 or more, or drop "
                        "predecessor:");
        return false;
    }
    return true;
}

static bool contract_cross_checks(unsigned seen, const struct engine_contract *c,
                                  char *reason, size_t cap)
{
    return contract_required_present(seen, c, reason, cap)
           && contract_rule_evidence_items(c, reason, cap)
           && contract_rule_source_only_executed_pass(c, reason, cap)
           && contract_rule_scope(c, reason, cap)
           && contract_rule_refs(c, reason, cap)
           && contract_rule_attempt(c, reason, cap);
}

enum engine_contract_result engine_contract_check(
    const char *task, size_t len, struct engine_contract *view,
    char *reason, size_t reason_cap)
{
    struct engine_contract local;
    struct engine_contract *c = view ? view : &local;
    struct contract_line ln[ENGINE_CONTRACT_MAX_HEADER_LINES];
    memset(c, 0, sizeof(*c));
    c->attempt = 1;
    if (reason && reason_cap)
        reason[0] = '\0';
    if (!task)
        return ENGINE_CONTRACT_LEGACY;
    if (memchr(task, '\0', len) != NULL) {
        contract_refuse(reason, reason_cap,
                        "contract refused: the task file contains a NUL byte; "
                        "remove it (a task is text)");
        return ENGINE_CONTRACT_REFUSED;
    }

    bool typed, over;
    const size_t count = contract_split(task, len, ln, &typed, &over);
    if (!typed)
        return ENGINE_CONTRACT_LEGACY;
    if (over || count > ENGINE_CONTRACT_MAX_FIELDS) {
        contract_refuse(reason, reason_cap,
                        "contract refused: typed header exceeds its bounds "
                        "(at most %u bytes, %u lines, %u fields)",
                        ENGINE_CONTRACT_MAX_HEADER_BYTES,
                        ENGINE_CONTRACT_MAX_HEADER_LINES,
                        ENGINE_CONTRACT_MAX_FIELDS);
        return ENGINE_CONTRACT_REFUSED;
    }
    unsigned seen = 0;
    for (size_t i = 0; i < count; i++) {
        if (!contract_line_apply(c, &seen, &ln[i], i + 1, reason, reason_cap))
            return ENGINE_CONTRACT_REFUSED;
    }
    if (!contract_cross_checks(seen, c, reason, reason_cap))
        return ENGINE_CONTRACT_REFUSED;
    return ENGINE_CONTRACT_OK;
}
