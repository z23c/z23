/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * muse_run_audit — the MEASURED facts one Muse run's verdict rests on,
 * split out of muse_run.c so the judgement and the measurement can each
 * be read in one sitting. Nothing here decides anything: every call
 * either reports a fact it measured or reports that it could not.
 *
 * THE SCOPE IS PROVEN BY MEASURED OUTPUT. The allow prefix handed to a
 * Muse session binds only the moment the model ASKS for approval; it
 * proves nothing about what the workspace holds afterwards. So a run
 * re-measures the change set through `git status --porcelain` and judges
 * every path that porcelain names.
 *
 * AN UNMEASURABLE ANSWER IS NEVER A CLEAN ONE. A failed spawn, a
 * non-zero or timed-out git, a capture that filled its bound, or a row
 * the parser could not read all report failure rather than a small
 * count. Every helper below that can fail says so in its return value,
 * and -1 always means UNMEASURABLE — never a measured zero.
 */
#ifndef ZCL_SERVICES_MUSE_RUN_AUDIT_H
#define ZCL_SERVICES_MUSE_RUN_AUDIT_H

#include <stdbool.h>
#include <stddef.h>

/* Bound on one git invocation made for measurement. A measurement that
 * cannot finish inside it is unmeasurable, which every caller refuses
 * on. */
#define MR_GIT_TIMEOUT_MS 60000

/* JSON string escaper for evidence fields (host- and model-minted text).
 * Truncates rather than overrunning, and the output is always valid. */
void muse_json_escape(const char *s, char *out, size_t cap);

/* True when s is exactly 40 lowercase hex digits and nothing else. An
 * identity that is not that shape was not read, and a partial identity
 * must never be compared as though it had been. */
bool muse_hex40(const char *s);

/* One captured git line, trailing newline trimmed. False on any failure;
 * identity is evidence, never judgement, so a caller degrades it to
 * "none" rather than guessing. */
bool muse_git_line(char *out, size_t cap, const char *workspace,
    const char *a1, const char *a2, const char *a3);

/* HEAD as one 40-hex identity. False when git could not name it, and out
 * degrades to the literal "none" so no reader mistakes an unread
 * identity for a match. */
bool muse_head_at(const char *workspace, char *out, size_t cap);

/* How many paths the workspace's porcelain names. -1 is UNMEASURABLE and
 * is never the same answer as 0, which is a measured clean tree. */
long long muse_files_changed(const char *workspace);

/* Dequote one C-quoted porcelain path in place ("a b" -> a b). False when
 * the quoting is MALFORMED — an unterminated quote, a backslash with
 * nothing after it, or an escape git never emits — because a best-effort
 * path out of a broken row is a path nothing can claim to have
 * measured. */
bool muse_dequote(char *path);

/* Inside the declared scope: the path IS the scope, or it lives under it.
 * A scope naming a directory admits its contents and never a sibling
 * whose name merely starts the same way ("docs/" never admits
 * "docsevil/x"), and any path carrying ".." or a leading '/' is outside
 * by definition. */
bool muse_scope_admits(const char *path, const char *scope);

/* A SCOPE is one to MUSE_SCOPE_MAX_PREFIXES repo-relative prefixes joined by
 * ',': a real fix and the test that proves it live under different roots,
 * and a one-prefix scope could only ever admit one of them. Valid means
 * every element is non-empty, relative (no leading '/' or '\\'), carries no
 * ".." segment, and the whole fits MUSE_RUN_SCOPE_MAX. */
#define MUSE_SCOPE_MAX_PREFIXES 4
bool muse_scope_valid(const char *scope);

/* Splits a valid scope into its prefixes: copies it into buf (cap bytes),
 * terminates each element in place and points out[] at them. Returns the
 * count, or 0 when the scope is not valid or does not fit. */
size_t muse_scope_prefixes(const char *scope, char *buf, size_t cap,
    const char *out[MUSE_SCOPE_MAX_PREFIXES]);

/* One measurement pass. scope NULL records the paths without judging
 * them: that is the pre-state pass, where any path at all is already a
 * refusal. The lists are bounded JSON array bodies (already escaped) and
 * may hold fewer elements than the counts beside them, which are always
 * the honest totals. */
struct muse_audit {
    const char *scope;
    char *list;
    size_t list_cap;
    size_t list_used;
    char *outside;
    size_t outside_cap;
    size_t outside_used;
    long long total;
    long long outside_total;
    /* Rows the parser could not read. Silently dropping one would hide a
     * path, so any non-zero value makes the whole pass unmeasurable. */
    long long unreadable;
    /* Why the FIRST unreadable row was unreadable, as a static string, or
     * NULL while every row read. A count alone says the audit stopped but
     * not what stopped it, and a refusal nobody can diagnose is one that
     * gets retried instead of repaired — so the reason travels with the
     * count into the caller's evidence. */
    const char *unreadable_why;
};

void muse_audit_init(struct muse_audit *a, const char *scope, char *list,
    size_t list_cap, char *outside, size_t outside_cap);

/* The measured change set, through the porcelain seam the diff count
 * already uses. False when the change set could not be MEASURED: a failed
 * allocation, a failed spawn, a non-zero or timed-out git, a capture that
 * filled its bound, or a row the parser could not read. Every one of
 * those is a refusal input. None of them may ever read as "clean" or as
 * "nothing outside scope" — a silent default there turns the whole audit
 * from a guarantee into decoration. */
bool muse_audit_scan(const char *workspace, struct muse_audit *a);

#endif /* ZCL_SERVICES_MUSE_RUN_AUDIT_H */
