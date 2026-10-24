/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_verify_capabilities — implementation of the receiver-side
 * capability re-derivation declared in vcs/package_verify_capabilities.h.
 * Read that header first: it carries the shipping decision for the symbol
 * table, the meaning of the three verdicts, and the honest list of what a
 * source-level scan cannot see. None of that is repeated here.
 *
 * Everything below reads bytes and compares strings. It compiles nothing,
 * executes nothing, opens no socket, resolves no include, and writes no file.
 * The only I/O is reading the caller-named table, the package manifest, and
 * the sources the manifest itself lists. */

#define _POSIX_C_SOURCE 200809L

#include "vcs/package_verify_capabilities.h"

#include "package_prepare_internal.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/positioned_file.h"
#include "sha3/sha3.h"
#include "vcs/package_manifest.h"

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── the anchor floor ────────────────────────────────────────────────
 *
 * Ten symbols whose class is not negotiable, compiled into the RECEIVER so
 * that a substituted table is caught with nothing pinned. A table that omits
 * one, or classifies one differently, is refused before it grades anything.
 * Declassifying connect is the whole point of substituting the table; this
 * is the first thing that refuses it.
 *
 * It is a FLOOR, not a checksum: a table that keeps these ten honest and
 * quietly declassifies a rarer entry point passes here and is caught only by
 * the digest pin. Both detectors exist for that reason. */
static const struct {
    const char *symbol;
    const char *class_name;
} k_pkgcap_anchors[] = {
    { "connect", "CAP_NETWORK" }, { "socket", "CAP_NETWORK" },
    { "bind", "CAP_NETWORK" },    { "listen", "CAP_NETWORK" },
    { "send", "CAP_NETWORK" },    { "recv", "CAP_NETWORK" },
    { "execve", "CAP_PROCESS" },  { "fork", "CAP_PROCESS" },
    { "dlopen", "CAP_DYNLOAD" },  { "setuid", "CAP_PRIVILEGE" },
};
#define PKGCAP_ANCHOR_COUNT \
    (sizeof(k_pkgcap_anchors) / sizeof(k_pkgcap_anchors[0]))

/* A symbol classified to this is a symbol somebody looked at and found
 * nothing to declare. It contributes no class. See the header of
 * engine/composition/capability_symbols.def for why it is spelled as a CAP_ id. */
#define PKGCAP_HARMLESS "CAP_HARMLESS"

#define PKGCAP_ROW_MARKER "ZCL_CAPABILITY_SYMBOL("

/* ── table ───────────────────────────────────────────────────────── */

struct pkgcap_row {
    char symbol[VCS_PKGCAP_SYMBOL_MAX];
    char class_name[VCS_PKGCAP_CLASS_MAX];
    bool used;
};

struct pkgcap_table {
    struct pkgcap_row *slots; /* open-addressed, power-of-two mask */
    size_t mask;
    uint32_t rows;
    uint32_t classified;
};

static void pkgcap_table_free(struct pkgcap_table *table)
{
    if (!table) return;
    free(table->slots);
    table->slots = NULL;
    table->mask = 0;
    table->rows = 0;
    table->classified = 0;
}

static uint64_t pkgcap_hash(const char *s, size_t len)
{
    uint64_t h = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)(unsigned char)s[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

/* Insert, first writer wins. A duplicate row cannot loosen a class: the
 * table file is expected to hold one row per symbol, and if it holds two the
 * first is kept rather than the last, so appending a declassifying duplicate
 * to the end of a table achieves nothing. */
static void pkgcap_table_put(struct pkgcap_table *table, const char *symbol,
                             size_t symbol_len, const char *class_name,
                             size_t class_len)
{
    size_t i = (size_t)pkgcap_hash(symbol, symbol_len) & table->mask;
    for (;;) {
        struct pkgcap_row *slot = &table->slots[i];
        if (!slot->used) {
            memcpy(slot->symbol, symbol, symbol_len);
            slot->symbol[symbol_len] = '\0';
            memcpy(slot->class_name, class_name, class_len);
            slot->class_name[class_len] = '\0';
            slot->used = true;
            table->rows++;
            if (strcmp(slot->class_name, PKGCAP_HARMLESS) != 0)
                table->classified++;
            return;
        }
        if (strncmp(slot->symbol, symbol, symbol_len) == 0 &&
            slot->symbol[symbol_len] == '\0')
            return; /* duplicate row: first writer wins */
        i = (i + 1) & table->mask;
    }
}

static const char *pkgcap_table_get(const struct pkgcap_table *table,
                                    const char *symbol, size_t symbol_len)
{
    if (!table->slots) return NULL;
    size_t i = (size_t)pkgcap_hash(symbol, symbol_len) & table->mask;
    for (;;) {
        const struct pkgcap_row *slot = &table->slots[i];
        if (!slot->used) return NULL;
        if (strncmp(slot->symbol, symbol, symbol_len) == 0 &&
            slot->symbol[symbol_len] == '\0')
            return slot->class_name;
        i = (i + 1) & table->mask;
    }
}

/* ── bounded whole-file read ─────────────────────────────────────────
 *
 * No fseek/ftell: neither is classified in engine/composition/capability_symbols.def, and
 * a size probe would not bound anything anyway (the file can grow between the
 * probe and the read). Read forward until the cap is exceeded, and refuse at
 * the cap rather than truncating — a truncated source is a source whose tail
 * was never scanned, and this file never grades what it did not read. */
static bool pkgcap_read_file(const char *path, size_t max_bytes,
                             char **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path)) return false;
    size_t cap = 65536;
    if (cap > max_bytes + 1) cap = max_bytes + 1;
    char *buf = zcl_malloc(cap, "pkgcap.file");
    if (!buf) {
        platform_positioned_file_close(&file);
        return false;
    }
    size_t len = 0;
    bool failed = false;
    for (;;) {
        if (len == cap) {
            if (cap > max_bytes) break; /* one byte past the cap: refuse */
            size_t next = cap * 2;
            if (next > max_bytes + 1) next = max_bytes + 1;
            char *grown = zcl_realloc(buf, next, "pkgcap.file");
            if (!grown) {
                free(buf);
                platform_positioned_file_close(&file);
                return false;
            }
            buf = grown;
            cap = next;
        }
        int64_t got = platform_positioned_file_read(
            &file, buf + len, cap - len, len);
        if (got < 0) {
            failed = true;
            break;
        }
        len += (size_t)got;
        if (got == 0) break;
    }
    bool overflow = len > max_bytes;
    platform_positioned_file_close(&file);
    if (overflow || failed) {
        free(buf);
        return false;
    }
    *out = buf;
    *out_len = len;
    return true;
}

/* ── report plumbing ─────────────────────────────────────────────── */

static bool pkgcap_verdict(struct vcs_pkgcap_report *out,
                           enum vcs_pkgcap_verdict verdict,
                           enum vcs_pkgcap_rule rule, const char *fmt, ...)
{
    out->verdict = (uint8_t)verdict;
    out->rule = (uint8_t)rule;
    va_list ap;
    va_start(ap, fmt);
    if (fmt)
        (void)vsnprintf(out->detail, sizeof(out->detail), fmt, ap);
    else
        out->detail[0] = '\0';
    va_end(ap);
    return verdict == VCS_PKGCAP_VERIFIED;
}

/* ── class sets ──────────────────────────────────────────────────── */

static bool pkgcap_set_has(const struct vcs_pkgcap_class_set *set,
                           const char *name)
{
    for (uint32_t i = 0; i < set->count; i++)
        if (strcmp(set->names[i], name) == 0) return true;
    return false;
}

static bool pkgcap_set_add(struct vcs_pkgcap_class_set *set, const char *name)
{
    if (pkgcap_set_has(set, name)) return false;
    if (set->count >= VCS_PKGCAP_MAX_CLASSES) {
        set->truncated = true;
        return false;
    }
    (void)snprintf(set->names[set->count], VCS_PKGCAP_CLASS_MAX, "%s", name);
    set->count++;
    return true;
}

/* ── the source-text scan ────────────────────────────────────────── */

static bool pkgcap_ident_start(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

static bool pkgcap_ident_char(char c)
{
    return pkgcap_ident_start(c) || (c >= '0' && c <= '9');
}

/* THE NAME IN THE SOURCE IS NOT ALWAYS THE NAME nm REPORTS, and the table is
 * keyed on what nm reports, because that string is what the object-level gate
 * matches. Fortification rewrites fprintf to __fprintf_chk and open to
 * __open_2 during translation; C23 rewrites sscanf to __isoc23_sscanf. The
 * source text spells none of those. Measured on this tree's own registry
 * before this probe existed: three of the ten packages derived an empty
 * FS_WRITE where the object tree sees __fprintf_chk, purely because the
 * source says fprintf.
 *
 * So each identifier is looked up under FOUR spellings — its own, __NAME_chk,
 * __isoc23_NAME and __NAME_2 — and the derived reach is the UNION of what
 * they classify to, not the first hit. The receiver does not know which
 * spelling this text will compile to (that is the toolchain's decision, made
 * long after the package shipped), so it must assume any of them. The union
 * is the fail-closed choice for the same reason an inactive `#if` arm is
 * scanned: a class that only some builds reach is still a class this text can
 * reach.
 *
 * This RECOVERS a known, mechanical rewrite. It is not a general answer to
 * "a name formed at preprocessing time", and the header says so: a decoration
 * family this receiver has never heard of is still a miss. */
#define PKGCAP_SPELLINGS 4u

static uint32_t pkgcap_lookup(const struct pkgcap_table *table,
                              const char *ident, size_t ident_len,
                              const char *out[PKGCAP_SPELLINGS])
{
    static const struct {
        const char *prefix;
        const char *suffix;
    } k_decorations[] = {
        { "", "" }, { "__", "_chk" }, { "__isoc23_", "" }, { "__", "_2" },
    };
    uint32_t found = 0;
    for (size_t d = 0; d < PKGCAP_SPELLINGS; d++) {
        const char *cls;
        if (d == 0) {
            cls = pkgcap_table_get(table, ident, ident_len);
        } else {
            char decorated[VCS_PKGCAP_SYMBOL_MAX];
            int w = snprintf(decorated, sizeof(decorated), "%s%.*s%s",
                             k_decorations[d].prefix, (int)ident_len, ident,
                             k_decorations[d].suffix);
            if (w < 0 || (size_t)w >= sizeof(decorated)) continue;
            cls = pkgcap_table_get(table, decorated, (size_t)w);
        }
        if (!cls || strcmp(cls, PKGCAP_HARMLESS) == 0) continue;
        bool dup = false;
        for (uint32_t k = 0; k < found; k++)
            if (strcmp(out[k], cls) == 0) dup = true;
        if (!dup) out[found++] = cls;
    }
    return found;
}

struct pkgcap_scan_ctx {
    const struct pkgcap_table *table;
    struct vcs_pkgcap_report *report;
    const char *rel_path;
};

/* One reach found. Records at most one finding per DISTINCT class — the
 * first occurrence — which is the evidence a reader needs ("this class, from
 * this file, this line, this symbol") without letting one noisy file fill
 * the whole array and hide a second class behind it. */
static void pkgcap_record(struct pkgcap_scan_ctx *ctx, const char *class_name,
                          const char *symbol, size_t symbol_len,
                          uint32_t line, bool call_shaped)
{
    struct vcs_pkgcap_report *r = ctx->report;
    if (pkgcap_set_has(&r->derived, class_name)) return;
    if (!pkgcap_set_add(&r->derived, class_name)) {
        r->findings_truncated = true;
        return;
    }
    if (r->finding_count >= VCS_PKGCAP_MAX_FINDINGS) {
        r->findings_truncated = true;
        return;
    }
    struct vcs_pkgcap_finding *f = &r->findings[r->finding_count++];
    (void)snprintf(f->class_name, sizeof(f->class_name), "%s", class_name);
    size_t copy = symbol_len < sizeof(f->symbol) - 1 ? symbol_len
                                                     : sizeof(f->symbol) - 1;
    memcpy(f->symbol, symbol, copy);
    f->symbol[copy] = '\0';
    (void)snprintf(f->file, sizeof(f->file), "%s", ctx->rel_path);
    f->line = line;
    f->call_shaped = call_shaped;
    f->outside_claim = !pkgcap_set_has(&r->claimed, class_name);
}

/* Walk one shipped source. Comments, string literals and character literals
 * are excluded; an identifier preceded by `.` or `->` is a member access and
 * is excluded; a `#include` line is skipped whole, so `<sys/socket.h>` does
 * not read as a socket call. No preprocessor runs — see the header for what
 * that costs in both directions. */

/* The scan position. prev1 and prev2 are the two bytes before i, which is all
 * the member-access test needs; line is the 1-based line of text[i]; line_start
 * is true until the first token of a line has been read. */
struct pkgcap_scan_pos {
    size_t i;
    uint32_t line;
    char prev1;
    char prev2;
    bool line_start;
};

static void pkgcap_scan_push(struct pkgcap_scan_pos *cur, char c)
{
    cur->prev2 = cur->prev1;
    cur->prev1 = c;
}

/* Newlines, horizontal space and a backslash-newline splice. A spliced line
 * stays the same logical line. */
static bool pkgcap_scan_blank(const char *text, size_t len,
                              struct pkgcap_scan_pos *cur)
{
    char c = text[cur->i];
    if (c == '\n') {
        cur->line++;
        cur->line_start = true;
        cur->i++;
        return true;
    }
    if (c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v') {
        cur->i++;
        return true;
    }
    if (c == '\\' && cur->i + 1 < len && text[cur->i + 1] == '\n') {
        cur->line++;
        cur->i += 2;
        return true;
    }
    return false;
}

static void pkgcap_skip_block_comment(const char *text, size_t len,
                                      struct pkgcap_scan_pos *cur)
{
    cur->i += 2;
    while (cur->i + 1 < len &&
           !(text[cur->i] == '*' && text[cur->i + 1] == '/')) {
        if (text[cur->i] == '\n') cur->line++;
        cur->i++;
    }
    cur->i = cur->i + 1 < len ? cur->i + 2 : len;
    pkgcap_scan_push(cur, '\0');
}

/* Line and block comments. Neither touches line_start. */
static bool pkgcap_scan_comment(const char *text, size_t len,
                                struct pkgcap_scan_pos *cur)
{
    char c = text[cur->i];
    if (c == '/' && cur->i + 1 < len && text[cur->i + 1] == '/') {
        cur->i += 2;
        while (cur->i < len && text[cur->i] != '\n') cur->i++;
        return true;
    }
    if (c == '/' && cur->i + 1 < len && text[cur->i + 1] == '*') {
        pkgcap_skip_block_comment(text, len, cur);
        return true;
    }
    return false;
}

/* True when the keyword `include` starts at j and is not a longer identifier. */
static bool pkgcap_is_include_word(const char *text, size_t len, size_t j)
{
    if (j + 7 > len || strncmp(text + j, "include", 7) != 0) return false;
    return j + 7 == len || !pkgcap_ident_char(text[j + 7]);
}

/* Consume to the end of a directive line, through its splices. The newline
 * that ends the line is left for the caller. */
static void pkgcap_skip_directive_line(const char *text, size_t len,
                                       struct pkgcap_scan_pos *cur)
{
    while (cur->i < len && text[cur->i] != '\n') {
        if (text[cur->i] == '\\' && cur->i + 1 < len &&
            text[cur->i + 1] == '\n') {
            cur->line++;
            cur->i++;
        }
        cur->i++;
    }
}

/* A `#include` line at the start of a line names header paths, not calls.
 * Returns false, with nothing consumed, when the line is not an include. */
static bool pkgcap_skip_include(const char *text, size_t len,
                                struct pkgcap_scan_pos *cur)
{
    size_t j = cur->i + 1;
    while (j < len && (text[j] == ' ' || text[j] == '\t')) j++;
    if (!pkgcap_is_include_word(text, len, j)) return false;
    pkgcap_skip_directive_line(text, len, cur);
    return true;
}

/* String and character literals. The quote is pushed as the previous byte. */
static bool pkgcap_scan_literal(const char *text, size_t len,
                                struct pkgcap_scan_pos *cur)
{
    char quote = text[cur->i];
    if (quote != '"' && quote != '\'') return false;
    cur->i++;
    while (cur->i < len && text[cur->i] != quote) {
        if (text[cur->i] == '\\' && cur->i + 1 < len) {
            if (text[cur->i + 1] == '\n') cur->line++;
            cur->i++;
        } else if (text[cur->i] == '\n') {
            cur->line++;
        }
        cur->i++;
    }
    if (cur->i < len) cur->i++;
    pkgcap_scan_push(cur, quote);
    return true;
}

/* An identifier that names a capability symbol is a reach. Each class it
 * classifies to is recorded, with whether the name is call-shaped. */
static void pkgcap_reach_ident(struct pkgcap_scan_ctx *ctx, const char *text,
                               size_t len, const struct pkgcap_scan_pos *cur,
                               size_t start, size_t ident_len)
{
    const char *classes[PKGCAP_SPELLINGS];
    uint32_t n = pkgcap_lookup(ctx->table, text + start, ident_len, classes);
    if (n == 0) return;
    size_t j = cur->i;
    while (j < len && (text[j] == ' ' || text[j] == '\t' ||
                       text[j] == '\n' || text[j] == '\r'))
        j++;
    bool call_shaped = j < len && text[j] == '(';
    for (uint32_t k = 0; k < n; k++)
        pkgcap_record(ctx, classes[k], text + start, ident_len, cur->line,
                      call_shaped);
}

static void pkgcap_scan_ident(struct pkgcap_scan_ctx *ctx, const char *text,
                              size_t len, struct pkgcap_scan_pos *cur)
{
    size_t start = cur->i;
    while (cur->i < len && pkgcap_ident_char(text[cur->i])) cur->i++;
    size_t ident_len = cur->i - start;
    bool member = (cur->prev1 == '.' && cur->prev2 != '.') ||
                  (cur->prev1 == '>' && cur->prev2 == '-');
    pkgcap_scan_push(cur, text[cur->i - 1]);
    if (member || ident_len >= VCS_PKGCAP_SYMBOL_MAX) return;
    pkgcap_reach_ident(ctx, text, len, cur, start, ident_len);
}

/* One token, or one run of trivia, from the cursor. Every call advances i. */
static void pkgcap_scan_step(struct pkgcap_scan_ctx *ctx, const char *text,
                             size_t len, struct pkgcap_scan_pos *cur)
{
    char c = text[cur->i];
    if (pkgcap_scan_blank(text, len, cur) ||
        pkgcap_scan_comment(text, len, cur))
        return;
    if (c == '#' && cur->line_start && pkgcap_skip_include(text, len, cur))
        return;
    cur->line_start = false;
    if (pkgcap_scan_literal(text, len, cur)) return;
    if (pkgcap_ident_start(c)) {
        pkgcap_scan_ident(ctx, text, len, cur);
        return;
    }
    pkgcap_scan_push(cur, c);
    cur->i++;
}

static void pkgcap_scan_source(struct pkgcap_scan_ctx *ctx, const char *text,
                               size_t len)
{
    struct pkgcap_scan_pos cur = {
        .i = 0, .line = 1, .prev1 = '\0', .prev2 = '\0', .line_start = true
    };
    while (cur.i < len) pkgcap_scan_step(ctx, text, len, &cur);
}

/* ── table load ──────────────────────────────────────────────────── */

/* Parse engine/composition/capability_symbols.def row form:
 *     ZCL_CAPABILITY_SYMBOL("<symbol>", CAP_<CLASS>, "<note>")
 * The marker must be followed by a quoted symbol, which is what keeps the
 * prose occurrence of the macro name in that file's own header comment from
 * parsing as a row. The class always sits on the opening line, exactly as
 * the shell readers in tools/lint assume, so a row wrapped by a long note
 * still parses. */
static bool pkgcap_row_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static size_t pkgcap_skip_row_space(const char *text, size_t len, size_t j)
{
    while (j < len && pkgcap_row_space(text[j])) j++;
    return j;
}

/* Count the row markers. The index is sized from this count, not from a
 * guess: a fixed table that silently stops inserting once it fills would DROP
 * rows — and a dropped row is a declassified symbol, which is exactly what a
 * substituted table is for. */
static size_t pkgcap_count_markers(const char *text, size_t len)
{
    const size_t marker_len = sizeof(PKGCAP_ROW_MARKER) - 1;
    size_t markers = 0;
    for (size_t k = 0; k + marker_len <= len; k++)
        if (memcmp(text + k, PKGCAP_ROW_MARKER, marker_len) == 0) {
            markers++;
            k += marker_len - 1;
        }
    return markers;
}

/* Four slots per marker, so the open addressing never runs hot. */
static bool pkgcap_table_alloc(struct pkgcap_table *out, size_t markers)
{
    size_t slot_count = 1024;
    while (slot_count < markers * 4 + 8) {
        if (slot_count > (size_t)1 << 24) return false;
        slot_count *= 2;
    }
    out->slots = zcl_calloc(slot_count, sizeof(*out->slots), "pkgcap.table");
    if (!out->slots) return false;
    out->mask = slot_count - 1;
    out->rows = 0;
    out->classified = 0;
    return true;
}

static size_t pkgcap_symbol_end(const char *text, size_t len, size_t j)
{
    while (j < len && text[j] != '"' && text[j] != '\n') j++;
    return j;
}

static size_t pkgcap_class_end(const char *text, size_t len, size_t j)
{
    while (j < len && ((text[j] >= 'A' && text[j] <= 'Z') ||
                       (text[j] >= '0' && text[j] <= '9') || text[j] == '_'))
        j++;
    return j;
}

static bool pkgcap_row_fields_ok(size_t sym_len, const char *cls,
                                 size_t cls_len)
{
    return sym_len > 0 && sym_len < VCS_PKGCAP_SYMBOL_MAX && cls_len > 4 &&
           cls_len < VCS_PKGCAP_CLASS_MAX && strncmp(cls, "CAP_", 4) == 0;
}

/* Read one row whose marker ends at `after`. A row that does not parse
 * returns `after`, so the caller resumes just past the marker; a row that
 * parses returns the index past its class. A long symbol pushes its class onto
 * the NEXT line — seven rows in this tree's own table do exactly that. A reader
 * that skipped only spaces and tabs dropped all seven silently, which is one
 * declassified symbol per dropped row. Newlines are whitespace here for that
 * reason, and the attempted/parsed comparison in the caller is what makes the
 * next such drop loud instead of silent. */
static size_t pkgcap_load_row(const char *text, size_t len, size_t after,
                              struct pkgcap_table *table, uint32_t *attempted,
                              uint32_t *parsed)
{
    size_t j = pkgcap_skip_row_space(text, len, after);
    /* The marker must be followed by a quoted symbol. That is what keeps the
     * prose occurrence of the macro name in the table file's own header
     * comment from parsing as a row, and it is why the attempted count is a
     * count of ROWS rather than of mentions. */
    if (j >= len || text[j] != '"') return after;
    (*attempted)++;
    size_t sym_start = j + 1;
    size_t sym_end = pkgcap_symbol_end(text, len, sym_start);
    if (sym_end >= len || text[sym_end] != '"') return after;
    size_t sym_len = sym_end - sym_start;
    j = pkgcap_skip_row_space(text, len, sym_end + 1);
    if (j >= len || text[j] != ',') return after;
    size_t cls_start = pkgcap_skip_row_space(text, len, j + 1);
    j = pkgcap_class_end(text, len, cls_start);
    size_t cls_len = j - cls_start;
    if (pkgcap_row_fields_ok(sym_len, text + cls_start, cls_len)) {
        pkgcap_table_put(table, text + sym_start, sym_len, text + cls_start,
                         cls_len);
        (*parsed)++;
    }
    return j;
}

static bool pkgcap_table_load(const char *text, size_t len,
                              struct pkgcap_table *out, uint32_t *attempted,
                              uint32_t *parsed)
{
    const size_t marker_len = sizeof(PKGCAP_ROW_MARKER) - 1;
    if (!pkgcap_table_alloc(out, pkgcap_count_markers(text, len))) return false;
    *attempted = 0;
    *parsed = 0;

    size_t i = 0;
    while (i + marker_len <= len) {
        if (memcmp(text + i, PKGCAP_ROW_MARKER, marker_len) != 0) {
            i++;
            continue;
        }
        i = pkgcap_load_row(text, len, i + marker_len, out, attempted, parsed);
    }
    return true;
}

/* ── shipped-source enumeration ──────────────────────────────────── */

struct pkgcap_sources {
    char (*paths)[VCS_PKGCAP_PATH_MAX];
    uint32_t count;
    bool overflow;
};

static void pkgcap_sources_free(struct pkgcap_sources *s)
{
    free(s->paths);
    s->paths = NULL;
    s->count = 0;
}

static bool pkgcap_is_scannable(const char *path)
{
    size_t n = strlen(path);
    if (n < 3) return false;
    return (path[n - 2] == '.' && (path[n - 1] == 'c' || path[n - 1] == 'h'));
}

static bool pkgcap_sources_add(struct pkgcap_sources *s, const char *path)
{
    if (s->count >= VCS_PKGCAP_MAX_SOURCES) {
        s->overflow = true;
        return false;
    }
    if (strlen(path) >= VCS_PKGCAP_PATH_MAX) {
        s->overflow = true;
        return false;
    }
    (void)snprintf(s->paths[s->count], VCS_PKGCAP_PATH_MAX, "%s", path);
    s->count++;
    return true;
}

/* The fallback when the manifest declares no `files` array: the package ships
 * its whole tree, and the compilable part of that is src plus tests. This is
 * the same rule zcode_pkg_sources() in tools/lint states, deliberately — if
 * the two disagreed about which files are shipped, one of them would be
 * grading a set the other never sees. */
static bool pkgcap_sources_from_dir(const char *package_dir, const char *sub,
                                    struct pkgcap_sources *out)
{
    char dir[VCS_PKGCAP_PATH_MAX * 2];
    int wrote = snprintf(dir, sizeof(dir), "%s/%s", package_dir, sub);
    if (wrote < 0 || (size_t)wrote >= sizeof(dir)) return false;
    DIR *d = opendir(dir);
    if (!d) return true; /* an absent subdirectory ships nothing */
    struct dirent *ent;
    bool ok = true;
    while ((ent = readdir(d)) != NULL) {
        size_t n = strlen(ent->d_name);
        if (n < 3 || ent->d_name[n - 2] != '.' || ent->d_name[n - 1] != 'c')
            continue;
        char rel[VCS_PKGCAP_PATH_MAX];
        int rw = snprintf(rel, sizeof(rel), "%s/%s", sub, ent->d_name);
        if (rw < 0 || (size_t)rw >= sizeof(rel)) {
            ok = false;
            continue;
        }
        if (!pkgcap_sources_add(out, rel)) ok = false;
    }
    (void)closedir(d);
    return ok;
}

/* ── the entry point ─────────────────────────────────────────────── */

static bool pkgcap_claim_load(const struct json_value *meta,
                              struct vcs_pkgcap_report *out)
{
    const struct json_value *caps = json_get(meta, "capabilities");
    if (!caps)
        return pkgcap_verdict(
            out, VCS_PKGCAP_UNPROVEN, VCS_PKGCAP_RULE_CLAIM_ABSENT,
            "manifest has no \"capabilities\" field: absent is not empty, and "
            "\"nobody wrote it down\" is not a proof of inertness");
    if (caps->type != JSON_ARR)
        return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                              VCS_PKGCAP_RULE_CLAIM_MALFORMED,
                              "\"capabilities\" is not an array");
    const char *prev = NULL;
    for (size_t i = 0; i < caps->num_children; i++) {
        const struct json_value *entry = &caps->children[i];
        if (entry->type != JSON_STR)
            return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                                  VCS_PKGCAP_RULE_CLAIM_MALFORMED,
                                  "\"capabilities\" entry %zu is not a string",
                                  i);
        const char *s = json_get_str(entry);
        if (!s || strncmp(s, "CAP_", 4) != 0 || s[4] == '\0' ||
            strlen(s) >= VCS_PKGCAP_CLASS_MAX)
            return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                                  VCS_PKGCAP_RULE_CLAIM_MALFORMED,
                                  "\"capabilities\" entry %zu is not a CAP_ "
                                  "class name",
                                  i);
        /* Strictly ascending and duplicate-free: the manifest bytes are
         * hashed into the package root, so two spellings of one set would be
         * two roots for one package. */
        if (prev && strcmp(prev, s) >= 0)
            return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                                  VCS_PKGCAP_RULE_CLAIM_MALFORMED,
                                  "\"capabilities\" not strictly ascending: "
                                  "%s after %s",
                                  s, prev);
        prev = s;
        if (!pkgcap_set_add(&out->claimed, s))
            return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                                  VCS_PKGCAP_RULE_LIMIT_EXCEEDED,
                                  "\"capabilities\" names more than %u "
                                  "classes",
                                  (unsigned)VCS_PKGCAP_MAX_CLASSES);
    }
    return true;
}

/* Each stage below that refuses leaves its verdict in out, frees what it was
 * handed, and returns false. A stage that passes hands on what it built: the
 * table and the manifest flow forward until the sources stage frees them. */

static bool pkgcap_options_ok(const struct vcs_pkgcap_options *options,
                              struct vcs_pkgcap_report *out)
{
    if (!options || !options->package_dir || !options->package_dir[0])
        return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                              VCS_PKGCAP_RULE_NULL_ARGUMENT,
                              "no package directory supplied");
    if (!options->table_path || !options->table_path[0])
        return pkgcap_verdict(
            out, VCS_PKGCAP_UNPROVEN, VCS_PKGCAP_RULE_NO_TABLE,
            "no capability symbol table supplied: without one the claim can "
            "only be believed, and a believed claim is what this check "
            "exists to replace");
    return true;
}

/* Read the table and pin its digest. The bytes stay with the caller. */
static bool pkgcap_table_pinned(const struct vcs_pkgcap_options *options,
                                struct vcs_pkgcap_report *out, char **text,
                                size_t *len)
{
    if (!pkgcap_read_file(options->table_path, VCS_PKGCAP_MAX_TABLE_BYTES,
                          text, len))
        return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                              VCS_PKGCAP_RULE_NO_TABLE,
                              "capability symbol table unreadable: %s",
                              options->table_path);

    zcl_sha3_256((const unsigned char *)*text, *len, out->table_digest);
    out->has_table_digest = true;

    if (options->expected_table_digest &&
        memcmp(out->table_digest, options->expected_table_digest, 32) != 0) {
        free(*text);
        return pkgcap_verdict(
            out, VCS_PKGCAP_UNPROVEN, VCS_PKGCAP_RULE_TABLE_DIGEST_MISMATCH,
            "capability symbol table is not the pinned one: a substituted "
            "table grades the claim it was chosen to clear");
    }
    return true;
}

/* Index the table text. The text is freed on both outcomes. */
static bool pkgcap_table_index(char *text, size_t len,
                               struct vcs_pkgcap_report *out,
                               struct pkgcap_table *table, uint32_t *attempted,
                               uint32_t *parsed)
{
    if (!pkgcap_table_load(text, len, table, attempted, parsed)) {
        free(text);
        pkgcap_table_free(table);
        return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                              VCS_PKGCAP_RULE_TABLE_HOLLOW,
                              "capability symbol table could not be indexed");
    }
    free(text);
    out->table_rows = table->rows;
    out->table_rows_classified = table->classified;
    return true;
}

/* A table that declassifies an anchor is a substituted table. */
static bool pkgcap_table_anchors(struct vcs_pkgcap_report *out,
                                 struct pkgcap_table *table)
{
    for (size_t i = 0; i < PKGCAP_ANCHOR_COUNT; i++) {
        const char *cls = pkgcap_table_get(table, k_pkgcap_anchors[i].symbol,
                                           strlen(k_pkgcap_anchors[i].symbol));
        if (cls && strcmp(cls, k_pkgcap_anchors[i].class_name) == 0) continue;
        char detail[VCS_PKGCAP_DETAIL_MAX];
        (void)snprintf(detail, sizeof(detail),
                       "capability symbol table classifies %s as %s, not %s: "
                       "a table that declassifies an anchor is a substituted "
                       "table",
                       k_pkgcap_anchors[i].symbol, cls ? cls : "nothing",
                       k_pkgcap_anchors[i].class_name);
        pkgcap_table_free(table);
        return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                              VCS_PKGCAP_RULE_TABLE_UNSOUND, "%s", detail);
    }
    return true;
}

/* Whether the indexed table is one this receiver understood in full. */
static bool pkgcap_table_sound(struct vcs_pkgcap_report *out,
                               struct pkgcap_table *table, uint32_t attempted,
                               uint32_t parsed)
{
    /* A row this reader started and did not finish is a symbol that silently
     * became unclassified, which is indistinguishable from a substituted
     * table that deleted it. Refuse rather than grade a package against a
     * table this receiver only partly understood. */
    if (parsed != attempted) {
        pkgcap_table_free(table);
        return pkgcap_verdict(
            out, VCS_PKGCAP_UNPROVEN, VCS_PKGCAP_RULE_TABLE_UNSOUND,
            "capability symbol table has %u row(s) this reader could not "
            "parse (%u of %u): an unread row is an unclassified symbol",
            attempted - parsed, parsed, attempted);
    }
    if (table->rows < VCS_PKGCAP_MIN_TABLE_ROWS || table->classified == 0) {
        uint32_t rows = table->rows;
        uint32_t classified = table->classified;
        pkgcap_table_free(table);
        return pkgcap_verdict(
            out, VCS_PKGCAP_UNPROVEN, VCS_PKGCAP_RULE_TABLE_HOLLOW,
            "capability symbol table parsed %u row(s), %u classified: every "
            "package would derive the empty set off a table that saw nothing",
            rows, classified);
    }
    return pkgcap_table_anchors(out, table);
}

/* ── table: read, digest, pin, index, sanity ─────────────────────── */
static bool pkgcap_table_stage(const struct vcs_pkgcap_options *options,
                               struct vcs_pkgcap_report *out,
                               struct pkgcap_table *table)
{
    char *text = NULL;
    size_t len = 0;
    if (!pkgcap_table_pinned(options, out, &text, &len)) return false;
    uint32_t attempted = 0;
    uint32_t parsed = 0;
    if (!pkgcap_table_index(text, len, out, table, &attempted, &parsed))
        return false;
    return pkgcap_table_sound(out, table, attempted, parsed);
}

/* ── the manifest and its claim ──────────────────────────────────── */
static bool pkgcap_manifest_stage(const struct vcs_pkgcap_options *options,
                                  struct vcs_pkgcap_report *out,
                                  struct pkgcap_table *table,
                                  struct json_value *meta)
{
    char manifest_path[VCS_PKGCAP_PATH_MAX * 2];
    int wrote = snprintf(manifest_path, sizeof(manifest_path),
                         "%s/zcode-package.json", options->package_dir);
    if (wrote < 0 || (size_t)wrote >= sizeof(manifest_path)) {
        pkgcap_table_free(table);
        return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                              VCS_PKGCAP_RULE_LIMIT_EXCEEDED,
                              "package directory path is too long");
    }
    char *meta_text = NULL;
    size_t meta_len = 0;
    if (!pkgcap_read_file(manifest_path, VCS_PKGCAP_MAX_MANIFEST_BYTES,
                          &meta_text, &meta_len)) {
        pkgcap_table_free(table);
        return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                              VCS_PKGCAP_RULE_NO_MANIFEST,
                              "no readable manifest at %s", manifest_path);
    }
    json_init(meta);
    if (!json_read(meta, meta_text, meta_len) || meta->type != JSON_OBJ) {
        json_free(meta);
        free(meta_text);
        pkgcap_table_free(table);
        return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                              VCS_PKGCAP_RULE_MANIFEST_UNPARSEABLE,
                              "manifest is not a JSON object");
    }
    free(meta_text);
    char shape_detail[128] = "";
    if (!prepare_meta_closed(meta, shape_detail, sizeof(shape_detail))) {
        json_free(meta);
        pkgcap_table_free(table);
        return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                              VCS_PKGCAP_RULE_MANIFEST_UNPARSEABLE,
                              "manifest is not the closed C23 package shape%s%s",
                              shape_detail[0] ? ": " : "", shape_detail);
    }
    if (!pkgcap_claim_load(meta, out)) {
        json_free(meta);
        pkgcap_table_free(table);
        return false;
    }
    return true;
}

/* The shipped files a manifest's `files` array declares. A non-C entry is
 * skipped; a non-string or non-canonical entry refuses the listing. */
static bool pkgcap_list_declared(const struct json_value *files,
                                 struct pkgcap_sources *sources)
{
    bool listing_ok = true;
    for (size_t i = 0; i < files->num_children; i++) {
        const char *p = json_get_str(&files->children[i]);
        if (!p) {
            listing_ok = false;
            continue;
        }
        if (!pkgcap_is_scannable(p)) continue;
        /* A shipped path that is not canonical is a traversal attempt or
         * a manifest this receiver cannot follow; either way it is not a
         * file to quietly skip. */
        if (!vcs_package_path_valid(p)) {
            listing_ok = false;
            continue;
        }
        if (!pkgcap_sources_add(sources, p)) listing_ok = false;
    }
    return listing_ok;
}

/* Both subtrees are listed even when the first fails. */
static bool pkgcap_list_by_convention(const char *package_dir,
                                      struct pkgcap_sources *sources)
{
    bool src_ok = pkgcap_sources_from_dir(package_dir, "src", sources);
    bool tests_ok = pkgcap_sources_from_dir(package_dir, "tests", sources);
    return src_ok && tests_ok;
}

static bool pkgcap_list_sources(const struct vcs_pkgcap_options *options,
                                const struct json_value *meta,
                                struct pkgcap_sources *sources)
{
    const struct json_value *files = json_get(meta, "files");
    if (files && files->type == JSON_ARR)
        return pkgcap_list_declared(files, sources);
    return pkgcap_list_by_convention(options->package_dir, sources);
}

/* Read one shipped source and record its reach. */
static bool pkgcap_scan_one(const struct vcs_pkgcap_options *options,
                            struct vcs_pkgcap_report *out,
                            struct pkgcap_table *table,
                            struct pkgcap_sources *sources, uint32_t i)
{
    char path[VCS_PKGCAP_PATH_MAX * 2];
    int w = snprintf(path, sizeof(path), "%s/%s", options->package_dir,
                     sources->paths[i]);
    if (w < 0 || (size_t)w >= sizeof(path)) {
        pkgcap_sources_free(sources);
        pkgcap_table_free(table);
        return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                              VCS_PKGCAP_RULE_LIMIT_EXCEEDED,
                              "shipped path is too long: %s",
                              sources->paths[i]);
    }
    char *text = NULL;
    size_t text_len = 0;
    if (!pkgcap_read_file(path, VCS_PKGCAP_MAX_SOURCE_BYTES, &text,
                          &text_len)) {
        char rel[VCS_PKGCAP_PATH_MAX];
        (void)snprintf(rel, sizeof(rel), "%s", sources->paths[i]);
        pkgcap_sources_free(sources);
        pkgcap_table_free(table);
        return pkgcap_verdict(
            out, VCS_PKGCAP_UNPROVEN, VCS_PKGCAP_RULE_SOURCE_UNREADABLE,
            "shipped source %s could not be read to the end: an unread "
            "file is not a clean file",
            rel);
    }
    struct pkgcap_scan_ctx ctx = {
        .table = table, .report = out, .rel_path = sources->paths[i]
    };
    pkgcap_scan_source(&ctx, text, text_len);
    free(text);
    out->sources_scanned++;
    return true;
}

/* ── derive ───────────────────────────────────────────────────────── */
static bool pkgcap_derive_reach(const struct vcs_pkgcap_options *options,
                                struct vcs_pkgcap_report *out,
                                struct pkgcap_table *table,
                                struct pkgcap_sources *sources)
{
    for (uint32_t i = 0; i < sources->count; i++)
        if (!pkgcap_scan_one(options, out, table, sources, i)) return false;
    pkgcap_sources_free(sources);
    pkgcap_table_free(table);

    if (out->derived.truncated || out->findings_truncated)
        return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                              VCS_PKGCAP_RULE_LIMIT_EXCEEDED,
                              "derived more than %u distinct classes",
                              (unsigned)VCS_PKGCAP_MAX_CLASSES);
    return true;
}

/* ── what it ships ───────────────────────────────────────────────── */
static bool pkgcap_sources_stage(const struct vcs_pkgcap_options *options,
                                 struct vcs_pkgcap_report *out,
                                 struct pkgcap_table *table,
                                 struct json_value *meta)
{
    struct pkgcap_sources sources = { 0 };
    sources.paths = zcl_calloc(VCS_PKGCAP_MAX_SOURCES,
                               sizeof(*sources.paths), "pkgcap.sources");
    if (!sources.paths) {
        json_free(meta);
        pkgcap_table_free(table);
        return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                              VCS_PKGCAP_RULE_LIMIT_EXCEEDED,
                              "could not allocate the shipped-source list");
    }
    bool listing_ok = pkgcap_list_sources(options, meta, &sources);
    json_free(meta);
    out->sources_listed = sources.count;

    if (!listing_ok || sources.overflow) {
        pkgcap_sources_free(&sources);
        pkgcap_table_free(table);
        return pkgcap_verdict(out, VCS_PKGCAP_UNPROVEN,
                              VCS_PKGCAP_RULE_LIMIT_EXCEEDED,
                              "shipped-file list is not one this receiver can "
                              "enumerate exactly");
    }
    if (sources.count == 0) {
        pkgcap_sources_free(&sources);
        pkgcap_table_free(table);
        return pkgcap_verdict(
            out, VCS_PKGCAP_UNPROVEN, VCS_PKGCAP_RULE_NO_SHIPPED_SOURCES,
            "package ships zero C sources: deriving the empty set from an "
            "empty file list would clear it without reading a line");
    }
    return pkgcap_derive_reach(options, out, table, &sources);
}

/* ── compare ──────────────────────────────────────────────────────── */

/* The first derived class the manifest does not claim, with one piece of
 * evidence for it when a finding names it. */
static void pkgcap_find_excess(const struct vcs_pkgcap_report *out,
                               const char **excess,
                               const struct vcs_pkgcap_finding **evidence)
{
    for (uint32_t i = 0; i < out->derived.count; i++) {
        if (pkgcap_set_has(&out->claimed, out->derived.names[i])) continue;
        *excess = out->derived.names[i];
        for (uint32_t f = 0; f < out->finding_count; f++)
            if (strcmp(out->findings[f].class_name, *excess) == 0) {
                *evidence = &out->findings[f];
                break;
            }
        break;
    }
}

static bool pkgcap_claims_reached(struct vcs_pkgcap_report *out)
{
    for (uint32_t i = 0; i < out->claimed.count; i++) {
        if (pkgcap_set_has(&out->derived, out->claimed.names[i])) continue;
        /* The claim is wider than the reach this scan can see. The receiver
         * is safe (it confines to the wider claim) but the claim is NOT
         * verified: the scan under-approximates, so it cannot tell an
         * over-declaring publisher from its own blind spot, and calling that
         * VERIFIED is the conflation this file exists to prevent. */
        return pkgcap_verdict(
            out, VCS_PKGCAP_UNPROVEN, VCS_PKGCAP_RULE_CLAIM_NOT_REACHED,
            "manifest claims %s and no shipped source names a symbol in it: "
            "a source scan cannot tell over-declaration from its own blind "
            "spots",
            out->claimed.names[i]);
    }
    return pkgcap_verdict(out, VCS_PKGCAP_VERIFIED, VCS_PKGCAP_RULE_MATCH,
                          NULL);
}

static bool pkgcap_compare(struct vcs_pkgcap_report *out)
{
    const char *excess = NULL;
    const struct vcs_pkgcap_finding *evidence = NULL;
    pkgcap_find_excess(out, &excess, &evidence);
    out->no_excess_reach = excess == NULL &&
                           out->sources_scanned == out->sources_listed;

    if (excess)
        return pkgcap_verdict(
            out, VCS_PKGCAP_REFUSED, VCS_PKGCAP_RULE_REACH_EXCEEDS_CLAIM,
            "%s is reached by %s%s%s but the manifest does not claim it",
            excess, evidence ? evidence->file : "a shipped source",
            evidence ? " via " : "", evidence ? evidence->symbol : "");
    return pkgcap_claims_reached(out);
}

bool vcs_package_verify_capabilities(const struct vcs_pkgcap_options *options,
                                     struct vcs_pkgcap_report *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->verdict = (uint8_t)VCS_PKGCAP_UNPROVEN;
    out->rule = (uint8_t)VCS_PKGCAP_RULE_NULL_ARGUMENT;

    if (!pkgcap_options_ok(options, out)) return false;
    struct pkgcap_table table = { 0 };
    if (!pkgcap_table_stage(options, out, &table)) return false;
    struct json_value meta = { 0 };
    if (!pkgcap_manifest_stage(options, out, &table, &meta)) return false;
    if (!pkgcap_sources_stage(options, out, &table, &meta)) return false;
    return pkgcap_compare(out);
}
