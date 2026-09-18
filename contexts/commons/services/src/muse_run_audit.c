/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the MEASURED facts one Muse run's verdict rests on — the
 * workspace's commit identity, the change set its porcelain names, and
 * whether each named path is inside the declared scope. See header. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "services/muse_run_audit.h"
#include "services/muse_run.h"
#include "base/safe_alloc.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Bound on one porcelain capture. zcl_spawn_capture discards whatever
 * overruns its buffer and still reports the child's exit status, so a
 * capture that fills its bound is INDISTINGUISHABLE from a complete one
 * and must be treated as unmeasurable, never as a short change set. */
#define MR_AUDIT_MAX (256u * 1024u)

void muse_json_escape(const char *s, char *out, size_t cap)
{
    size_t n = 0;
    if (!s) s = "";
    while (*s && n + 6 < cap) {
        unsigned char c = (unsigned char)*s++;
        if (c == '"' || c == '\\') {
            out[n++] = '\\';
            out[n++] = (char)c;
        } else if (c < 0x20) {
            int w = snprintf(out + n, cap - n, "\\u%04x", c);
            if (w <= 0 || (size_t)w >= cap - n) break;
            n += (size_t)w;
        } else {
            out[n++] = (char)c;
        }
    }
    out[n] = '\0';
}

/* --- measured helpers ------------------------------------------------------ */

/* True when a capture filled its bound: the helper silently discards the
 * overrun, so a full buffer proves only that the measurement is unknown. */
static bool mr_capture_truncated(const char *buf, size_t cap)
{
    return cap == 0 || strlen(buf) + 1 >= cap;
}

/* -1 is UNMEASURABLE and is never the same answer as 0, which is a
 * measured clean tree: a failed spawn, a non-zero git, or a capture that
 * filled its bound all refuse rather than under-report the count. */
long long muse_files_changed(const char *workspace)
{
    const char *argv[] = { "git", "-C", workspace, "status", "--porcelain",
                           NULL };
    char *buf = zcl_malloc(MR_AUDIT_MAX, "muse_run.git_out");
    long long count = 0;
    int rc;
    if (!buf) return -1;
    buf[0] = '\0';
    rc = zcl_spawn_capture(argv, buf, MR_AUDIT_MAX, MR_GIT_TIMEOUT_MS);
    if (rc != 0 || mr_capture_truncated(buf, MR_AUDIT_MAX)) {
        free(buf);
        return -1;
    }
    for (const char *p = buf; *p; p++) {
        if (*p == '\n') count++;
    }
    free(buf);
    return count;
}

/* One captured git line, trailing newline trimmed. False on any failure;
 * identity is evidence, never judgement, so failure degrades to "none". */
bool muse_git_line(char *out, size_t cap, const char *workspace,
    const char *a1, const char *a2, const char *a3)
{
    const char *argv[] = { "git", "-C", workspace, a1, a2, a3, NULL };
    char *buf = zcl_malloc(65536, "muse_run.git_line");
    int rc;
    size_t n;
    if (!buf || !out || cap == 0) {
        free(buf);
        return false;
    }
    buf[0] = '\0';
    rc = zcl_spawn_capture(argv, buf, 65536, MR_GIT_TIMEOUT_MS);
    if (rc != 0) {
        free(buf);
        return false;
    }
    n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] =
        '\0';
    if (n == 0 || n >= cap) {
        free(buf);
        return false;
    }
    memcpy(out, buf, n + 1);
    free(buf);
    return true;
}

bool muse_hex40(const char *s)
{
    int i;
    if (!s) return false;
    for (i = 0; i < 40; i++) {
        char c = s[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) return false;
    }
    return s[40] == '\0';
}

/* HEAD, as one 40-hex identity. False when git could not name it, and the
 * field degrades to the literal "none" so no reader mistakes an unread
 * identity for a match. An identity that is not 40 hex is unread: this is
 * an equality test later, and a partial answer would compare unequal for
 * the wrong reason. */
bool muse_head_at(const char *workspace, char *out, size_t cap)
{
    if (muse_git_line(out, cap, workspace, "rev-parse", "HEAD", NULL) &&
        muse_hex40(out))
        return true;
    (void)snprintf(out, cap, "none");
    return false;
}

/* The escapes git emits after a backslash in a C-quoted path, paired with
 * the byte each one stands for. Anything else is a row this parser did not
 * write, so it cannot claim to have read it either. */
static const char mr_escape_from[] = "abfnrtv\\\"";
static const char mr_escape_to[] = "\a\b\f\n\r\t\v\\\"";

/* One backslash escape, resolved into *w. p points at the character AFTER
 * the backslash; returns the last character consumed, or NULL when the
 * escape is not one git emits. */
static const char *mr_unescape(const char *p, char **w)
{
    const char *hit;
    if (!*p) return NULL;
    if (*p >= '0' && *p <= '7') {
        int v = 0, k = 0;
        while (k < 3 && *p >= '0' && *p <= '7') {
            v = v * 8 + (*p - '0');
            p++;
            k++;
        }
        *(*w)++ = (char)v;
        return p - 1;
    }
    hit = strchr(mr_escape_from, *p);
    if (!hit) return NULL;
    *(*w)++ = mr_escape_to[hit - mr_escape_from];
    return p;
}

/* Dequote one C-quoted porcelain path in place ("a b" -> a b). False when
 * the quoting is MALFORMED — an unterminated quote, a backslash with
 * nothing after it, or an escape git never emits. A best-effort path out
 * of a broken row is a path this audit cannot claim to have measured, and
 * every caller turns that into a refusal rather than a judgement. */
bool muse_dequote(char *path)
{
    char *w;
    size_t n = strlen(path);
    if (n == 0) return true;
    if (path[0] != '"') return strchr(path, '"') == NULL;
    if (n < 2 || path[n - 1] != '"') return false;
    path[n - 1] = '\0';
    w = path;
    for (const char *p = path + 1; *p; p++) {
        if (*p != '\\') {
            *w++ = *p;
            continue;
        }
        if (!p[1]) return false;
        p = mr_unescape(p + 1, &w);
        if (!p) return false;
    }
    *w = '\0';
    return true;
}

/* --- the scope audit ------------------------------------------------------
 * THE MODEL PROPOSES. THE GATE DECIDES — and the SCOPE is decided here, by
 * measured output. The allow prefix handed to the session binds only the
 * moment the model asks for approval; it proves nothing about what the
 * workspace holds afterwards. So the run re-measures the change set through
 * the SAME `git status --porcelain` invocation muse_files_changed counts, and
 * judges every path it names. */

/* Inside the declared scope: the path IS the scope, or it lives under it.
 * A scope naming a directory admits its contents and never a sibling whose
 * name merely starts the same way ("docs/" never admits "docsevil/x"), and
 * any path carrying ".." or a leading '/' is outside by definition. */
static bool mr_prefix_admits(const char *path, const char *scope, size_t n)
{
    while (n > 0 && scope[n - 1] == '/') n--;
    if (n == 0) return false;
    if (strncmp(path, scope, n) != 0) return false;
    if (path[n] == '\0') return true;
    return path[n] == '/';
}

/* Any one prefix of the scope admits the path. */
bool muse_scope_admits(const char *path, const char *scope)
{
    const char *at;
    if (!path || !path[0] || !scope || !scope[0]) return false;
    if (path[0] == '/' || strstr(path, "..") != NULL) return false;
    for (at = scope;;) {
        const char *end = strchr(at, ',');
        size_t n = end ? (size_t)(end - at) : strlen(at);
        if (mr_prefix_admits(path, at, n)) return true;
        if (!end) return false;
        at = end + 1;
    }
}

/* One element: non-empty, relative, and no ".." segment. */
static bool mr_prefix_valid(const char *p, size_t n)
{
    if (n == 0 || p[0] == '/' || p[0] == '\\') return false;
    for (size_t i = 0; i + 1 < n; i++) {
        if (p[i] == '.' && p[i + 1] == '.' &&
            (i == 0 || p[i - 1] == '/') &&
            (i + 2 == n || p[i + 2] == '/'))
            return false;
    }
    return true;
}

bool muse_scope_valid(const char *scope)
{
    size_t count = 0;
    const char *at;
    if (!scope || !scope[0] || strlen(scope) >= MUSE_RUN_SCOPE_MAX)
        return false;
    for (at = scope;;) {
        const char *end = strchr(at, ',');
        size_t n = end ? (size_t)(end - at) : strlen(at);
        if (++count > MUSE_SCOPE_MAX_PREFIXES || !mr_prefix_valid(at, n))
            return false;
        if (!end) return true;
        at = end + 1;
    }
}

size_t muse_scope_prefixes(const char *scope, char *buf, size_t cap,
    const char *out[MUSE_SCOPE_MAX_PREFIXES])
{
    size_t count = 0;
    char *at;
    if (!muse_scope_valid(scope) || !buf || strlen(scope) >= cap) return 0;
    memcpy(buf, scope, strlen(scope) + 1);
    for (at = buf; at && count < MUSE_SCOPE_MAX_PREFIXES;) {
        char *end = strchr(at, ',');
        if (end) *end = '\0';
        out[count++] = at;
        at = end ? end + 1 : NULL;
    }
    return count;
}

/* Appends one escaped element to a bounded JSON array body. False once the
 * bound is reached: one run's change set can never write without limit, and
 * the body stays valid JSON at every truncation point. */
static bool mr_list_push(char *buf, size_t cap, size_t *used,
    const char *path)
{
    char esc[1024];
    int w;
    if (!buf || cap == 0 || *used >= cap) return false;
    muse_json_escape(path, esc, sizeof(esc));
    w = snprintf(buf + *used, cap - *used, "%s\"%s\"",
        *used > 0 ? "," : "", esc);
    if (w <= 0 || (size_t)w >= cap - *used) {
        buf[*used] = '\0';
        return false;
    }
    *used += (size_t)w;
    return true;
}

void muse_audit_init(struct muse_audit *a, const char *scope, char *list,
    size_t list_cap, char *outside, size_t outside_cap)
{
    memset(a, 0, sizeof(*a));
    a->scope = scope;
    a->list = list;
    a->list_cap = list_cap;
    a->outside = outside;
    a->outside_cap = outside_cap;
    if (list && list_cap > 0) list[0] = '\0';
    if (outside && outside_cap > 0) outside[0] = '\0';
}

/* One row this parser could not read. The count is what makes the whole
 * pass unmeasurable; the reason is what makes that refusal actionable. A
 * measurement that can only say "I could not" and never "because" is a
 * measurement nobody can repair, so the FIRST reason is kept — later rows
 * are nearly always the same breakage repeated, and the first one is the
 * one still adjacent to whatever produced it. */
static void mr_unreadable(struct muse_audit *a, const char *why)
{
    a->unreadable++;
    if (!a->unreadable_why) a->unreadable_why = why;
}

/* One measured path: counted in full, recorded while the bound allows, and
 * judged against the scope. A row that names nothing is unreadable, never
 * an absence. */
static void mr_audit_path(struct muse_audit *a, const char *path)
{
    if (!path || !path[0]) {
        mr_unreadable(a, "a row named an empty path");
        return;
    }
    a->total++;
    (void)mr_list_push(a->list, a->list_cap, &a->list_used, path);
    if (!a->scope || muse_scope_admits(path, a->scope)) return;
    a->outside_total++;
    (void)mr_list_push(a->outside, a->outside_cap, &a->outside_used, path);
}

/* Every status character porcelain v1 can print in either column. */
static bool mr_status_char(char c)
{
    return c == ' ' || c == 'M' || c == 'T' || c == 'A' || c == 'D' ||
        c == 'R' || c == 'C' || c == 'U' || c == '?' || c == '!';
}

/* Why this row's fixed-width prefix is not one this audit can read, or
 * NULL when it reads. The prefix is exactly two legal status characters
 * and the single space that always follows them. '?' and '!' only ever
 * appear doubled, and two blanks mean "unmodified in both columns", which
 * this seam never prints. A line that is not that shape did not come out
 * of the porcelain this audit measures, so the caller counts it unreadable
 * instead of trusting the path it appears to carry: length alone is not a
 * shape, and a blind fixed skip over a line of the wrong shape invents a
 * path out of whatever follows.
 *
 * Each rejection names itself rather than collapsing into a bare false.
 * These six are not one condition: a short line, a status byte from some
 * other porcelain version, and a prefix that is the right length but the
 * wrong shape are three different breakages with three different fixes,
 * and a refusal that cannot tell them apart hands its reader nothing to
 * act on. */
static const char *mr_row_status_why(const char *line)
{
    if (!line || strlen(line) < 4)
        return "a row too short to carry a status prefix and a path";
    if (!mr_status_char(line[0]) || !mr_status_char(line[1]))
        return "a status column that is not a porcelain v1 character";
    if (line[2] != ' ')
        return "no separating space after the two status columns";
    if ((line[0] == '?') != (line[1] == '?'))
        return "'?' in one status column only, never doubled";
    if ((line[0] == '!') != (line[1] == '!'))
        return "'!' in one status column only, never doubled";
    if (line[0] == ' ' && line[1] == ' ')
        return "both status columns blank, which this seam never prints";
    return NULL;
}

/* Whether the status names a second path. Rename and copy carry " -> " in
 * either column; nothing else does. */
static bool mr_row_names_two(const char *line)
{
    return line[0] == 'R' || line[0] == 'C' ||
        line[1] == 'R' || line[1] == 'C';
}

/* One porcelain row -> the path or paths it names. A rename row names two
 * paths and BOTH are judged: moving a file out of scope changes it just as
 * surely as editing it does. The shape must AGREE with the status: an
 * R/C row without its separator, or a separator on a status that cannot
 * carry one, is unreadable rather than one lucky path — either way the
 * row names something this parser did not identify, and a path it did not
 * identify is a path it did not judge. A literal " -> " inside a single
 * unquoted filename is ambiguous by the same rule and refuses too. */
static void mr_audit_row(struct muse_audit *a, char *line)
{
    const char *why = mr_row_status_why(line);
    char *arrow;
    bool two;
    if (why) {
        mr_unreadable(a, why);
        return;
    }
    two = mr_row_names_two(line);
    line += 3;
    arrow = strstr(line, " -> ");
    if (two != (arrow != NULL)) {
        mr_unreadable(a, two
            ? "a rename or copy row with no \" -> \" separator"
            : "a \" -> \" separator on a status that never carries one");
        return;
    }
    if (arrow) {
        *arrow = '\0';
        if (!muse_dequote(line)) {
            mr_unreadable(a, "malformed quoting on a rename source path");
            return;
        }
        mr_audit_path(a, line);
        line = arrow + 4;
    }
    if (!muse_dequote(line)) {
        mr_unreadable(a, "malformed quoting on a row's path");
        return;
    }
    mr_audit_path(a, line);
}

/* The measured change set, through the porcelain seam the diff count
 * already uses. False when the change set could not be MEASURED: a failed
 * allocation, a failed spawn, a non-zero or timed-out git, a capture that
 * filled its bound, or a row the parser could not read. Every one of those
 * is a refusal input. None of them may ever read as "clean" or as "nothing
 * outside scope" — a silent default there turns this whole audit from a
 * guarantee into decoration. */
bool muse_audit_scan(const char *workspace, struct muse_audit *a)
{
    /* -uall on purpose: the default collapses a wholly untracked
     * directory to its own name, and while that is still sound for the
     * judgement (the directory name is a prefix of everything inside it,
     * so a collapse can never hide an out-of-scope path), the changed
     * list IS the proof that the permission was respected. Name the
     * files. Same seam, same binary, one flag. */
    const char *argv[] = { "git", "-C", workspace, "status", "--porcelain",
                           "-uall", NULL };
    char *buf = zcl_malloc(MR_AUDIT_MAX, "muse_run.audit");
    int rc;
    bool ok;
    if (!buf) return false;
    buf[0] = '\0';
    rc = zcl_spawn_capture(argv, buf, MR_AUDIT_MAX, MR_GIT_TIMEOUT_MS);
    if (rc != 0 || mr_capture_truncated(buf, MR_AUDIT_MAX)) {
        free(buf);
        return false;
    }
    for (char *line = strtok(buf, "\n"); line; line = strtok(NULL, "\n"))
        mr_audit_row(a, line);
    ok = a->unreadable == 0;
    free(buf);
    return ok;
}
