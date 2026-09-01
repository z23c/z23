/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: lint gate E1 — the file-size policy for production C, written for
 * how an agent actually reads code.
 *
 * ── THE MODEL: one policy, three bands ──────────────────────────────────
 *
 *   TARGET = 800 lines.   Advisory. At or under it, a file is silent.
 *   BUFFER = 801..1500.   ALLOWED. Never fails, needs no baseline entry, and
 *                         produces no churn. This is where a file may live
 *                         and grow while somebody is working on it.
 *   LIMIT  = 1500 lines.  HARD. Over it fails, unless the file is carried in
 *                         the shrink-only legacy baseline.
 *
 * ── WHY 1500 ────────────────────────────────────────────────────────────
 *
 * An agent reads a source file in ONE tool call up to about 2000 lines. Past
 * that it must read in chunks and loses the whole-file view — which is the
 * exact moment its edits start being wrong, because it is reasoning about a
 * file it has never seen all of. A 1500-line hard limit keeps every
 * production file readable in a single call with real headroom, so nobody
 * hits that wall in the middle of an edit.
 *
 * ── WHY 800 STAYS THE TARGET ────────────────────────────────────────────
 *
 * Because it is already true. 1741 of the 1838 production C files (95%) are
 * at or under 800 lines with nobody enforcing it. That makes 800 a real norm
 * describing how this tree is actually written, not an aspiration — so it is
 * worth stating, and not worth failing a build over.
 *
 * ── WHY THERE IS A BUFFER AT ALL ────────────────────────────────────────
 *
 * The predecessor gate had a single 800-line ceiling plus a "drift count"
 * ratchet pinned at 0. Adding three lines to an 877-line file failed the
 * build and forced an emergency split in the middle of unrelated work. That
 * is a tax on every edit near the line and it buys nothing: a file at 877
 * lines is not a mega-module, it is a normal file. The buffer band exists so
 * ordinary growth is ordinary. The drift-count ratchet is DELETED.
 *
 * ── THE LEGACY BASELINE ─────────────────────────────────────────────────
 *
 * The files already over 1500 when this policy landed are listed in
 * tools/lint/file_size_policy_baseline.txt as `<path> <max-loc>`, one per
 * line, `#` comments allowed. Rules, all shrink-only:
 *
 *   - a baselined file that GROWS past its recorded number FAILS;
 *   - a baselined file that shrinks to <= LIMIT must have its row DELETED
 *     (this gate fails and says so, so a fix cannot leave a stale exemption);
 *   - a row naming a file this gate no longer scans is stale and FAILS;
 *   - a file NOT in the baseline that exceeds LIMIT FAILS. Nothing is ever
 *     added to the baseline: it only shrinks, it never grows.
 *
 * `--fix` lowers a recorded number to the file's current count and deletes
 * rows that are no longer needed. It can only tighten: it never raises a
 * number and never adds a row.
 *
 * ── THE ALLOWLIST ───────────────────────────────────────────────────────
 *
 * Straight-line generated or tabular code (crypto field-arithmetic tables,
 * generated windows) is long by nature, not by neglect, and line count says
 * nothing about it. Those files are skipped entirely — see ALLOWLIST below.
 *
 * ── USAGE ───────────────────────────────────────────────────────────────
 *
 *   file_size_policy              gate; exit 0 clean, 1 violations, 2 hollow
 *   file_size_policy --verbose    also list every file in the buffer band
 *   file_size_policy --fix        tighten/delete baseline rows, then gate
 *
 * Environment overrides (used by the self-tests in
 * tests/harness/src/lint_gate_shape_selftests.c; unset in normal runs):
 *
 *   ZCL_FILE_SIZE_POLICY_BASELINE     baseline file path
 *   ZCL_FILE_SIZE_POLICY_SCAN_ROOTS   ':'- or ' '-separated scan roots
 *   ZCL_LINT_PRODUCTION_SCAN=1        exclude transient lint fixtures and
 *                                     build/vendor noise (set by `make`; see
 *                                     tools/lint/scan_exclusions.sh)
 *
 * Paths are repo-relative and the gate finds the checkout by walking up from
 * the working directory, so it can be run from anywhere inside the tree.
 *
 * FAIL-CLOSED: if the walk yields zero files the gate exits 2 and refuses to
 * report clean. A gate that silently scans nothing is worse than no gate.
 */

#include "platform/directory_compat.h"
#include "base/safe_alloc.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GATE_NAME "check-file-size-ceiling"

/* ── The policy constants. These three numbers ARE the policy. ─────────── */
#define TARGET_LINES 800
#define LIMIT_LINES  1500

#define DEFAULT_BASELINE_PATH "tools/lint/file_size_policy_baseline.txt"
#define PATH_MAX_LEN 1024

/* Generated/tabular code: skipped entirely, never baselined. Carried over
 * verbatim from the predecessor gate's LIB_ALLOWLIST. */
static const char *const ALLOWLIST[] = {
    "core/modules/chain/src/sha3_windows.c",
    "core/modules/sapling/src/bn254.c",
    "core/modules/sapling/src/bls12_381.c",
    "contexts/wallet/domain/src/mnemonic.c",
};
#define ALLOWLIST_COUNT (sizeof ALLOWLIST / sizeof ALLOWLIST[0])

/* Closed legacy exemption set. The text baseline may delete a row or lower
 * its ceiling, but it cannot mint a new exemption or raise an old one. Keeping
 * the landing ceilings in compiled policy makes that promise enforceable. */
struct legacy_ceiling {
    const char *path;
    long maximum;
};
static const struct legacy_ceiling LEGACY_CEILINGS[] = {
    { "engine/composition/src/boot.c", 4001 },
    { "engine/composition/src/boot_refold_staged.c", 1810 },
    { "cognition/modules/codeindex/src/codeindex_merkle.c", 1776 },
    { "engine/modules/hotswap/src/hotswap_activate.c", 2325 },
    { "engine/modules/kernel/src/command_registry.c", 2403 },
    { "core/modules/net/src/connman.c", 3432 },
    { "core/modules/net/src/download.c", 1793 },
    { "core/modules/net/src/fast_sync.c", 1688 },
    { "core/modules/net/src/file_service.c", 3058 },
    { "core/modules/net/src/msg_headers.c", 2370 },
    { "core/modules/net/src/msgprocessor.c", 3031 },
    { "core/modules/net/src/msgprocessor_snapshot.c", 1810 },
    { "core/modules/net/src/net.c", 2373 },
    { "core/modules/net/src/onion_directory.c", 1516 },
    { "core/modules/net/src/peer_lifecycle.c", 1634 },
    { "core/modules/net/src/rom_fetch.c", 1599 },
    { "platform/modules/platform/src/os_sandbox_linux.c", 1526 },
    { "contexts/commons/modules/vcs/src/package_reward.c", 1986 },
    { "contexts/commons/modules/vcs/src/package_swarm_node.c", 2015 },
    { "contexts/commons/modules/vcs/src/vcs_devloop.c", 2390 },
    { "contexts/wallet/modules/wallet/src/wallet.c", 1560 },
    { "contexts/wallet/modules/wallet/src/wallet_sqlite.c", 1603 },
    { "engine/entry/main_cli_modes.c", 4275 },
};
#define LEGACY_CEILING_COUNT \
    (sizeof LEGACY_CEILINGS / sizeof LEGACY_CEILINGS[0])

/* Scan roots. depth 0 = unlimited; depth 1 = that directory's own files
 * only (src/ holds the binary's composition entrypoint and nothing deeper). */
struct scan_root {
    const char *path;
    int max_depth;
};
static const struct scan_root DEFAULT_ROOTS[] = {
    { "core",       0 },
    { "engine",     0 },
    { "contexts",   0 },
    { "cognition",  0 },
    { "platform",   0 },
};
#define DEFAULT_ROOT_COUNT (sizeof DEFAULT_ROOTS / sizeof DEFAULT_ROOTS[0])

/* ── Baseline model ─────────────────────────────────────────────────────── */

enum row_state {
    ROW_UNSEEN = 0,   /* no scanned file matched this row -> stale */
    ROW_HELD,         /* still over LIMIT, at or under its recorded number */
    ROW_GROWN,        /* over its recorded number -> FAIL */
    ROW_TIGHTENABLE,  /* still over LIMIT but smaller -> advisory, --fix lowers */
    ROW_RETIRED,      /* now <= LIMIT -> row must be deleted */
};

struct baseline_row {
    char path[PATH_MAX_LEN];
    long recorded;
    long observed;
    enum row_state state;
};

struct policy_run {
    struct baseline_row *rows;
    size_t row_count;
    size_t row_cap;

    char **buffer_files;   /* files in the 801..LIMIT band, for --verbose */
    size_t buffer_count;
    size_t buffer_cap;

    char **over_limit;     /* over LIMIT and NOT baselined -> FAIL */
    size_t over_count;
    size_t over_cap;
    long  *over_loc;
    size_t over_loc_cap;

    size_t scanned;
    size_t at_target;
    size_t allowlisted;
    bool   walk_failed;
};

static void die_oom(void)
{
    fprintf(stderr, GATE_NAME ": FATAL — out of memory\n");
    exit(2);
}

static char *dup_str(const char *s)
{
    size_t n = strlen(s) + 1;
    char *out = zcl_malloc(n, "file_size_policy_str");
    if (!out) die_oom();
    memcpy(out, s, n);
    return out;
}

static void push_str(char ***vec, size_t *count, size_t *cap, const char *s)
{
    if (*count == *cap) {
        size_t next = *cap ? *cap * 2 : 64;
        char **grown = zcl_realloc(*vec, next * sizeof(**vec),
                                   "file_size_policy_vec");
        if (!grown) die_oom();
        *vec = grown;
        *cap = next;
    }
    (*vec)[(*count)++] = dup_str(s);
}

static struct baseline_row *find_row(struct policy_run *run, const char *path)
{
    for (size_t i = 0; i < run->row_count; i++)
        if (strcmp(run->rows[i].path, path) == 0)
            return &run->rows[i];
    return NULL;
}

static long legacy_ceiling_for(const char *path)
{
    for (size_t i = 0; i < LEGACY_CEILING_COUNT; i++)
        if (strcmp(LEGACY_CEILINGS[i].path, path) == 0)
            return LEGACY_CEILINGS[i].maximum;
    return -1;
}

/* ── Repo-root anchoring ────────────────────────────────────────────────
 *
 * Every path this gate reports is repo-relative, and it must find the tree
 * whatever directory it is invoked from (the predecessor script did this by
 * `cd`-ing to the repo root; chdir is not in C23 and differs on Win32, so
 * this prefixes instead). Walk up from the working directory looking for a
 * directory that holds BOTH Makefile and tools/lint/scan_exclusions.sh, and
 * remember the "../../" prefix that reaches it. Not finding it is FATAL —
 * scanning some unrelated directory would be worse than not scanning. */
static char g_root_prefix[PATH_MAX_LEN] = "";

static bool path_is_absolute(const char *p)
{
    if (p[0] == '/' || p[0] == '\\') return true;
    return p[0] != '\0' && p[1] == ':';   /* C:\... on Win32 */
}

/* Repo-relative path -> the path to actually open. */
static void root_join(char *out, size_t out_size, const char *rel)
{
    if (path_is_absolute(rel) || g_root_prefix[0] == '\0')
        snprintf(out, out_size, "%s", rel);
    else
        snprintf(out, out_size, "%s%s", g_root_prefix, rel);
}

static bool file_exists(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    fclose(fp);
    return true;
}

static bool find_repo_root(void)
{
    char prefix[PATH_MAX_LEN] = "";
    char probe[PATH_MAX_LEN];
    for (int depth = 0; depth < 8; depth++) {
        snprintf(probe, sizeof probe, "%sMakefile", prefix);
        if (file_exists(probe)) {
            snprintf(probe, sizeof probe, "%stools/lint/scan_exclusions.sh",
                     prefix);
            if (file_exists(probe)) {
                memcpy(g_root_prefix, prefix, strlen(prefix) + 1);
                return true;
            }
        }
        size_t len = strlen(prefix);
        if (len + 4 >= sizeof prefix) break;
        memcpy(prefix + len, "../", 4);
    }
    return false;
}

/* Load `<path> <max-loc>` rows. A missing baseline file is not an error —
 * a tree with nothing over the limit legitimately has no baseline. */
static bool load_baseline(struct policy_run *run, const char *file)
{
    char abs_path[PATH_MAX_LEN];
    root_join(abs_path, sizeof abs_path, file);
    FILE *fp = fopen(abs_path, "rb");
    if (!fp) return true;
    const bool enforce_closed_set = strcmp(file, DEFAULT_BASELINE_PATH) == 0;

    char line[PATH_MAX_LEN + 64];
    while (fgets(line, (int)sizeof line, fp)) {
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char *path_start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
        if (p == path_start) continue;
        size_t path_len = (size_t)(p - path_start);
        if (path_len >= PATH_MAX_LEN) continue;
        char *num = p;
        while (*num == ' ' || *num == '\t') num++;
        path_start[path_len] = '\0';
        long recorded = strtol(num, NULL, 10);
        if (recorded <= 0) continue;
        long ceiling = legacy_ceiling_for(path_start);
        if (enforce_closed_set && (ceiling < 0 || recorded > ceiling)) {
            fprintf(stderr, GATE_NAME ": FATAL — baseline row is not a "
                    "shrink-only legacy exemption: %s %ld\n",
                    path_start, recorded);
            run->walk_failed = true;
            continue;
        }

        if (run->row_count == run->row_cap) {
            size_t next = run->row_cap ? run->row_cap * 2 : 64;
            struct baseline_row *grown =
                zcl_realloc(run->rows, next * sizeof(*grown),
                            "file_size_policy_rows");
            if (!grown) die_oom();
            run->rows = grown;
            run->row_cap = next;
        }
        struct baseline_row *row = &run->rows[run->row_count++];
        memset(row, 0, sizeof *row);
        memcpy(row->path, path_start, path_len + 1);
        row->recorded = recorded;
        row->observed = -1;
        row->state = ROW_UNSEEN;
    }
    fclose(fp);
    return true;
}

/* Exactly what `wc -l` reports: the number of newline bytes. */
static long count_lines(const char *path)
{
    char abs_path[PATH_MAX_LEN];
    root_join(abs_path, sizeof abs_path, path);
    FILE *fp = fopen(abs_path, "rb");
    if (!fp) return -1;
    static char buf[65536];
    long lines = 0;
    size_t got;
    while ((got = fread(buf, 1, sizeof buf, fp)) > 0)
        for (size_t i = 0; i < got; i++)
            if (buf[i] == '\n') lines++;
    if (ferror(fp)) { fclose(fp); return -1; }
    fclose(fp);
    return lines;
}

/* ── Scan-set membership ────────────────────────────────────────────────── */

static bool production_scan(void)
{
    const char *v = getenv("ZCL_LINT_PRODUCTION_SCAN");
    return v && strcmp(v, "1") == 0;
}

static bool has_c_suffix(const char *name)
{
    size_t n = strlen(name);
    return n > 2 && name[n - 2] == '.' && name[n - 1] == 'c';
}

static bool is_allowlisted(const char *rel)
{
    for (size_t i = 0; i < ALLOWLIST_COUNT; i++)
        if (strcmp(rel, ALLOWLIST[i]) == 0) return true;
    return false;
}

/* Transient lint fixtures are named `_<...>fixture<...>.c` by convention
 * (tools/lint/scan_exclusions.sh). A gate's own self-test execs this binary
 * DIRECTLY, so ZCL_LINT_PRODUCTION_SCAN is unset there and its planted
 * fixture is seen; a concurrent `make lint` runs with it set and is immune. */
static bool is_transient_fixture(const char *name)
{
    return name[0] == '_' && strstr(name, "fixture") != NULL;
}

/* Directory names never walked. `test` covers tests/harness/include/test/ (fixtures and group
 * registrations, legitimately huge) and any domain module test/ dir. The rest is
 * build/vendor/worktree noise, excluded only under a production scan so a
 * self-test pointing the roots at test-tmp/ still sees its own fixtures. */
static bool skip_directory(const char *name, bool production)
{
    if (strcmp(name, "test") == 0) return true;
    if (!production) return false;
    return strcmp(name, "build") == 0 || strcmp(name, "vendor") == 0 ||
           strcmp(name, ".claude") == 0 || strcmp(name, "test-tmp") == 0 ||
           strcmp(name, "planted") == 0;
}

/* ── The walk. One pass, portable: platform/modules/platform's UTF-8 directory listing
 * backed by dirent on POSIX and FindFirstFileW on Win32. ───────────────── */

static void classify(struct policy_run *run, const char *rel, long loc)
{
    struct baseline_row *row = find_row(run, rel);
    if (row) {
        row->observed = loc;
        if (loc <= LIMIT_LINES)        row->state = ROW_RETIRED;
        else if (loc > row->recorded)  row->state = ROW_GROWN;
        else if (loc < row->recorded)  row->state = ROW_TIGHTENABLE;
        else                           row->state = ROW_HELD;
        if (loc > TARGET_LINES && loc <= LIMIT_LINES)
            push_str(&run->buffer_files, &run->buffer_count,
                     &run->buffer_cap, rel);
        else if (loc <= TARGET_LINES)
            run->at_target++;
        return;
    }
    if (loc <= TARGET_LINES) {
        run->at_target++;
    } else if (loc <= LIMIT_LINES) {
        push_str(&run->buffer_files, &run->buffer_count, &run->buffer_cap, rel);
    } else {
        push_str(&run->over_limit, &run->over_count, &run->over_cap, rel);
        if (run->over_loc_cap < run->over_cap) {
            long *locs = zcl_realloc(run->over_loc,
                                     run->over_cap * sizeof(*locs),
                                     "file_size_policy_over_loc");
            if (!locs) die_oom();
            run->over_loc = locs;
            run->over_loc_cap = run->over_cap;
        }
        run->over_loc[run->over_count - 1] = loc;
    }
}

static void walk(struct policy_run *run, const char *rel_dir, int depth,
                 int max_depth, bool production)
{
    struct platform_directory_list files = { 0 };
    char abs_dir[PATH_MAX_LEN];
    root_join(abs_dir, sizeof abs_dir, rel_dir);
    if (!platform_directory_list_regular_sorted(abs_dir, &files)) {
        fprintf(stderr, GATE_NAME ": FATAL — cannot list scan root %s\n",
                rel_dir);
        run->walk_failed = true;
        return;
    }
    for (size_t i = 0; i < files.count; i++) {
        const char *name = files.entries[i].name;
        if (!has_c_suffix(name)) continue;
        if (production && is_transient_fixture(name)) continue;
        char rel[PATH_MAX_LEN];
        if (snprintf(rel, sizeof rel, "%s/%s", rel_dir, name) >=
            (int)sizeof rel)
            continue;
        if (is_allowlisted(rel)) { run->allowlisted++; continue; }
        long loc = count_lines(rel);
        if (loc < 0) {
            fprintf(stderr, GATE_NAME ": FATAL — cannot read %s\n", rel);
            run->walk_failed = true;
            continue;
        }
        run->scanned++;
        classify(run, rel, loc);
    }
    platform_directory_list_free(&files);

    if (max_depth > 0 && depth + 1 >= max_depth) return;

    struct platform_directory_list dirs = { 0 };
    if (!platform_directory_list_real_sorted(abs_dir, &dirs)) {
        fprintf(stderr, GATE_NAME ": FATAL — cannot descend scan root %s\n",
                rel_dir);
        run->walk_failed = true;
        return;
    }
    for (size_t i = 0; i < dirs.count; i++) {
        const char *name = dirs.entries[i].name;
        if (skip_directory(name, production)) continue;
        char child[PATH_MAX_LEN];
        if (snprintf(child, sizeof child, "%s/%s", rel_dir, name) >=
            (int)sizeof child)
            continue;
        walk(run, child, depth + 1, max_depth, production);
    }
    platform_directory_list_free(&dirs);
}

/* ── Baseline rewrite (--fix). Tighten-only, by construction: it copies the
 * file line for line, lowers a number, or drops a row. It has no branch that
 * raises a number or appends one. ──────────────────────────────────────── */

static int rewrite_baseline(struct policy_run *run, const char *file)
{
    char abs_path[PATH_MAX_LEN];
    root_join(abs_path, sizeof abs_path, file);
    FILE *in = fopen(abs_path, "rb");
    if (!in) return 0;
    char tmp[PATH_MAX_LEN + 8];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", abs_path) >= (int)sizeof tmp) {
        fclose(in);
        return 0;
    }
    FILE *out = fopen(tmp, "wb");
    if (!out) { fclose(in); return 0; }

    int changed = 0;
    char line[PATH_MAX_LEN + 64];
    while (fgets(line, (int)sizeof line, in)) {
        char scratch[PATH_MAX_LEN + 64];
        memcpy(scratch, line, strlen(line) + 1);
        char *hash = strchr(scratch, '#');
        if (hash) *hash = '\0';
        char *p = scratch;
        while (*p == ' ' || *p == '\t') p++;
        char *path_start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
        size_t path_len = (size_t)(p - path_start);
        if (path_len == 0 || path_len >= PATH_MAX_LEN) {
            fputs(line, out);
            continue;
        }
        path_start[path_len] = '\0';
        struct baseline_row *row = find_row(run, path_start);
        if (!row) { fputs(line, out); continue; }
        if (row->state == ROW_TIGHTENABLE) {
            fprintf(out, "%s %ld\n", row->path, row->observed);
            changed++;
        } else if (row->state == ROW_RETIRED || row->state == ROW_UNSEEN) {
            changed++;   /* row dropped entirely */
        } else {
            fputs(line, out);
        }
    }
    fclose(in);
    fclose(out);
    if (changed == 0) { remove(tmp); return 0; }
    remove(abs_path);
    if (rename(tmp, abs_path) != 0) {
        fprintf(stderr, GATE_NAME ": FATAL — could not replace %s\n", file);
        exit(2);
    }
    return changed;
}

/* ── Reporting ──────────────────────────────────────────────────────────── */

static void report_failures(const struct policy_run *run, const char *baseline,
                            size_t fail_count)
{
    printf("\n" GATE_NAME ": FAIL — %zu file-size policy violation(s)\n\n",
           fail_count);

    for (size_t i = 0; i < run->over_count; i++) {
        printf("  OVER THE HARD LIMIT: %s\n", run->over_limit[i]);
        printf("    current: %ld lines. Hard limit: %d lines.\n",
               run->over_loc[i], LIMIT_LINES);
        printf("    Do this: split %s into separate files along its seams,\n",
               run->over_limit[i]);
        printf("    each at or under %d lines (the target). Anything up to %d\n",
               TARGET_LINES, LIMIT_LINES);
        printf("    lines is fine and needs no paperwork. Do NOT add a line to\n");
        printf("    %s — that list only shrinks.\n\n", baseline);
    }

    for (size_t i = 0; i < run->row_count; i++) {
        const struct baseline_row *row = &run->rows[i];
        if (row->state == ROW_GROWN) {
            printf("  LEGACY FILE GREW: %s\n", row->path);
            printf("    current: %ld lines. Its recorded number in %s is %ld.\n",
                   row->observed, baseline, row->recorded);
            printf("    Do this: bring %s back to %ld lines or fewer. This file\n",
                   row->path, row->recorded);
            printf("    predates the %d-line limit and is only allowed to get\n",
                   LIMIT_LINES);
            printf("    smaller; its recorded number may never be raised.\n\n");
        } else if (row->state == ROW_RETIRED) {
            printf("  STALE BASELINE ROW: %s\n", row->path);
            printf("    current: %ld lines, which is at or under the %d-line\n",
                   row->observed, LIMIT_LINES);
            printf("    limit, so it no longer needs an exemption.\n");
            printf("    Do this: delete the line `%s %ld` from %s\n",
                   row->path, row->recorded, baseline);
            printf("    (or run `file_size_policy --fix`).\n\n");
        } else if (row->state == ROW_UNSEEN) {
            printf("  STALE BASELINE ROW: %s\n", row->path);
            printf("    no such file in the scan set — it was deleted, renamed,\n");
            printf("    or moved out of the scanned trees.\n");
            printf("    Do this: delete the line `%s %ld` from %s\n",
                   row->path, row->recorded, baseline);
            printf("    (or run `file_size_policy --fix`).\n\n");
        }
    }

    printf("  Policy: target %d lines (advisory), %d-%d allowed with no\n",
           TARGET_LINES, TARGET_LINES + 1, LIMIT_LINES);
    printf("  paperwork, over %d fails. %d is the size a file can still be\n",
           LIMIT_LINES, LIMIT_LINES);
    printf("  read in one go; past it every later reader works blind.\n");
}

int main(int argc, char **argv)
{
    bool fix = false;
    bool verbose = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--fix") == 0) fix = true;
        else if (strcmp(argv[i], "--verbose") == 0 ||
                 strcmp(argv[i], "-v") == 0) verbose = true;
        else if (strcmp(argv[i], "--help") == 0) {
            printf("usage: file_size_policy [--fix] [--verbose]\n");
            printf("  target %d lines, buffer %d-%d, hard limit %d\n",
                   TARGET_LINES, TARGET_LINES + 1, LIMIT_LINES, LIMIT_LINES);
            return 0;
        } else {
            fprintf(stderr, GATE_NAME ": FATAL — unknown option '%s'\n",
                    argv[i]);
            return 2;
        }
    }

    if (!find_repo_root()) {
        fprintf(stderr, GATE_NAME ": FATAL — could not find the repository\n"
                        "  root from this directory (looked up 8 levels for a\n"
                        "  Makefile beside tools/lint/). Run it from inside a\n"
                        "  checkout; refusing to scan an unknown tree.\n");
        return 2;
    }

    const char *baseline = getenv("ZCL_FILE_SIZE_POLICY_BASELINE");
    if (!baseline || !*baseline) baseline = DEFAULT_BASELINE_PATH;

    struct policy_run run = { 0 };
    load_baseline(&run, baseline);

    bool production = production_scan();
    const char *roots_env = getenv("ZCL_FILE_SIZE_POLICY_SCAN_ROOTS");
    if (roots_env && *roots_env) {
        char *copy = dup_str(roots_env);
        char *save = copy;
        while (*save) {
            while (*save == ':' || *save == ' ') save++;
            if (!*save) break;
            char *end = save;
            while (*end && *end != ':' && *end != ' ') end++;
            char saved = *end;
            *end = '\0';
            walk(&run, save, 0, 0, production);
            *end = saved;
            save = end;
        }
        free(copy);
    } else {
        for (size_t i = 0; i < DEFAULT_ROOT_COUNT; i++)
            walk(&run, DEFAULT_ROOTS[i].path, 0, DEFAULT_ROOTS[i].max_depth,
                 production);
    }

    if (run.walk_failed) {
        fprintf(stderr, GATE_NAME ": FATAL — a file in the scan set could not "
                        "be read; refusing to report a verdict.\n");
        return 2;
    }

    /* Fail-closed floor. A walk that yields nothing means a scanned tree was
     * renamed, moved, or emptied — never that the tree is clean. */
    if (run.scanned == 0) {
        fprintf(stderr, GATE_NAME ": FATAL — scanned 0 files.\n");
        fprintf(stderr, "  The scan produced no *.c at all; a scanned "
                        "directory was renamed, moved, or deleted.\n");
        fprintf(stderr, "  Refusing to report 'clean' off a hollow scan.\n");
        return 2;
    }

    int fixed = fix ? rewrite_baseline(&run, baseline) : 0;
    if (fixed > 0)
        printf(GATE_NAME ": --fix tightened %d baseline row(s) in %s\n",
               fixed, baseline);

    size_t grown = 0, retired = 0, unseen = 0, held = 0, tightenable = 0;
    for (size_t i = 0; i < run.row_count; i++) {
        switch (run.rows[i].state) {
        case ROW_GROWN:       grown++; break;
        case ROW_RETIRED:     retired++; break;
        case ROW_UNSEEN:      unseen++; break;
        case ROW_HELD:        held++; break;
        case ROW_TIGHTENABLE: tightenable++; break;
        }
    }
    /* --fix already removed the retired/stale rows and lowered the tightenable
     * ones, so they are no longer violations on this run. */
    if (fixed > 0) {
        retired = 0; unseen = 0;
        held += tightenable; tightenable = 0;
    }

    size_t fail_count = run.over_count + grown + retired + unseen;
    if (fail_count > 0) {
        report_failures(&run, baseline, fail_count);
        return 1;
    }

    printf(GATE_NAME ": PASS — %zu files scanned: %zu at or under the %d-line "
           "target, %zu in the %d-%d buffer, %zu legacy over %d "
           "(shrink-only baseline), %zu allowlisted.\n",
           run.scanned, run.at_target, TARGET_LINES, run.buffer_count,
           TARGET_LINES + 1, LIMIT_LINES, held + tightenable, LIMIT_LINES,
           run.allowlisted);

    if (verbose && run.buffer_count > 0) {
        printf("\n  Buffer band (%d-%d lines — allowed, no action needed):\n",
               TARGET_LINES + 1, LIMIT_LINES);
        for (size_t i = 0; i < run.buffer_count; i++)
            printf("    %s\n", run.buffer_files[i]);
    }
    if (tightenable > 0) {
        printf("\n  Baseline can tighten (still over %d, but smaller than "
               "recorded) — run `--fix`:\n", LIMIT_LINES);
        for (size_t i = 0; i < run.row_count; i++)
            if (run.rows[i].state == ROW_TIGHTENABLE)
                printf("    %s is now %ld lines (recorded %ld)\n",
                       run.rows[i].path, run.rows[i].observed,
                       run.rows[i].recorded);
    }
    return 0;
}
