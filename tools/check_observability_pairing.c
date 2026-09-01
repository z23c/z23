/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Reject stderr diagnostics in changed app/lib C files unless the nearby
 * code also emits an observable event, propagates a terminal failure, or
 * carries an explicit obs-ok justification.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINES 4096
#define LINE_LEN 4096

static bool has_c_suffix(const char *path)
{
    size_t len = strlen(path);
    return len >= 2 && strcmp(path + len - 2, ".c") == 0;
}

static bool is_test_path(const char *path)
{
    return strncmp(path, "tests/harness/include/test/", 9) == 0 ||
           strstr(path, "/tests/harness/include/test/") != NULL;
}

static bool line_has_obs_ok(const char *line)
{
    /* Require `// obs-ok:<tag>` where <tag> starts with [A-Za-z]
     * and is followed by [A-Za-z0-9_-]+. Bare `// obs-ok` and empty
     * `// obs-ok:` or `// obs-ok: ` are rejected — every override
     * must declare a non-empty single-token reason so reviewers can
     * grep the taxonomy of justifications. */
    const char *tag = strstr(line, "// obs-ok:");
    if (!tag) return false;
    const char *p = tag + 10;
    if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z')))
        return false;
    p++;
    /* Require at least one more body char to make tags meaningful */
    return (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
           (*p >= '0' && *p <= '9') || *p == '_' || *p == '-';
}

static bool line_has_event_emit(const char *line)
{
    return strstr(line, "event_emit(") || strstr(line, "event_emitf(");
}

static bool line_has_terminal_propagation(const char *line)
{
    /* A bare `return;` in a void-returning helper is just as
     * terminal as `return false;` — the fprintf above was the
     * caller-visible observation, and control will not continue
     * past it on the error path. */
    if (strstr(line, "return;")) return true;
    return strstr(line, "return false;") ||
           strstr(line, "return -1;") ||
           strstr(line, "return 1;") ||
           strstr(line, "return NULL;") ||
           strstr(line, "return ZCL_ERR(") ||
           strstr(line, "exit(") ||
           strstr(line, "abort(");
}

static bool observability_line_allowed(char lines[][LINE_LEN], size_t count,
                                       size_t idx)
{
    /* Look 3 lines back (for event_emit / obs-ok preamble) and 6
     * lines forward (long enough to clear multi-line fprintf
     * statements that span 3-5 continuation lines before the
     * matching `return false;` / `return -1;` / `goto cleanup;`). */
    size_t start = idx > 3 ? idx - 3 : 0;
    size_t end = idx + 6 < count ? idx + 6 : count - 1;
    for (size_t i = start; i <= end; i++) {
        if (line_has_event_emit(lines[i])) return true;
        if (i >= idx && line_has_terminal_propagation(lines[i])) return true;
        /* Allow `// obs-ok:<tag>` on any line in the window — multi-
         * line fprintf statements often place the marker on a
         * continuation line near the format string. */
        if (line_has_obs_ok(lines[i])) return true;
    }
    return false;
}

static int check_file(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "check_observability_pairing: cannot open %s\n", path);
        return -1;
    }

    static char lines[MAX_LINES][LINE_LEN];
    memset(lines, 0, sizeof(lines));
    size_t count = 0;
    while (count < MAX_LINES && fgets(lines[count], sizeof(lines[count]), fp))
        count++;

    if (ferror(fp)) {
        fclose(fp);
        fprintf(stderr, "check_observability_pairing: read failed: %s\n", path);
        return -1;
    }
    fclose(fp);

    int bad = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(lines[i], "fprintf(stderr") &&
            !observability_line_allowed(lines, count, i)) {
            printf("%s:%zu:%s", path, i + 1, lines[i]);
            if (lines[i][0] == '\0' || lines[i][strlen(lines[i]) - 1] != '\n')
                printf("\n");
            bad = 1;
        }
    }
    return bad;
}

/* De-dup set so a file that appears in several git diff lists (e.g. both
 * the merge-base diff and the unstaged working-tree diff) is checked only
 * once. Paths are short and the change set is small, so a flat array with a
 * linear membership test is adequate and keeps the program dependency-free. */
#define MAX_SEEN 1024
struct seen_set {
    char paths[MAX_SEEN][LINE_LEN];
    size_t count;
};

static bool seen_contains(const struct seen_set *set, const char *path)
{
    for (size_t i = 0; i < set->count; i++)
        if (strcmp(set->paths[i], path) == 0)
            return true;
    return false;
}

static void seen_add(struct seen_set *set, const char *path)
{
    if (set->count >= MAX_SEEN) return;
    snprintf(set->paths[set->count], LINE_LEN, "%s", path);
    set->count++;
}

static int run_list_command(const char *cmd, int *checked, struct seen_set *seen)
{
    FILE *pipe = popen(cmd, "r");
    if (!pipe) {
        fprintf(stderr, "check_observability_pairing: command failed: %s\n", cmd);
        return -1;
    }

    int rc = 0;
    char path[LINE_LEN];
    while (fgets(path, sizeof(path), pipe)) {
        path[strcspn(path, "\n")] = '\0';
        if (!has_c_suffix(path) || is_test_path(path))
            continue;
        if (seen && seen_contains(seen, path))
            continue;
        if (seen) seen_add(seen, path);
        (*checked)++;
        int file_rc = check_file(path);
        if (file_rc < 0) rc = -1;
        if (file_rc > 0 && rc == 0) rc = 1;
    }

    int close_rc = pclose(pipe);
    if (close_rc != 0 && rc == 0) rc = -1;
    return rc;
}

static int read_first_line(const char *cmd, char *out, size_t outsz)
{
    FILE *pipe = popen(cmd, "r");
    if (!pipe) return -1;
    if (!fgets(out, outsz, pipe)) out[0] = '\0';
    out[strcspn(out, "\n")] = '\0';
    int close_rc = pclose(pipe);
    return close_rc == 0 && out[0] != '\0' ? 0 : -1;
}

/* Fold a command's rc into the running scan rc: any read/exec failure
 * (rc < 0) is sticky-fatal; any unpaired-diagnostic finding (rc > 0) wins
 * over a clean scan. */
static int fold_rc(int acc, int next)
{
    if (next < 0) return -1;
    if (next > 0 && acc == 0) return 1;
    return acc;
}

static int run_default_scan(int *checked)
{
    const char *scan_all = getenv("ZCL_OBS_SCAN_ALL");
    if (scan_all && strcmp(scan_all, "1") == 0) {
        return run_list_command("find app lib -type f -name '*.c' "
                                "! -path 'tests/harness/include/test/*' | sort",
                                checked, NULL);
    }

    /* Scan committed-since-merge-base AND the in-flight tree (unstaged +
     * staged) so a freshly modified app/lib .c file is checked before it
     * is committed. A shared seen-set de-dups files that appear in more
     * than one list. */
    static struct seen_set seen;
    seen.count = 0;
    int rc = 0;

    char base[128];
    if (read_first_line("git merge-base HEAD origin/main 2>/dev/null",
                        base, sizeof(base)) == 0) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd),
                 "git diff --name-only --diff-filter=ACMR %s -- app lib",
                 base);
        rc = fold_rc(rc, run_list_command(cmd, checked, &seen));
    } else {
        rc = fold_rc(rc, run_list_command(
            "git diff --name-only --diff-filter=ACMR -- app lib",
            checked, &seen));
    }

    /* Unstaged working-tree changes (git diff). */
    rc = fold_rc(rc, run_list_command(
        "git diff --name-only --diff-filter=ACMR -- app lib",
        checked, &seen));

    /* Staged-but-uncommitted changes (git diff --cached). */
    rc = fold_rc(rc, run_list_command(
        "git diff --cached --name-only --diff-filter=ACMR -- app lib",
        checked, &seen));

    return rc;
}

int main(int argc, char **argv)
{
    int rc = 0;
    int checked = 0;

    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            if (!has_c_suffix(argv[i]))
                continue;
            checked++;
            int file_rc = check_file(argv[i]);
            if (file_rc < 0) rc = -1;
            if (file_rc > 0 && rc == 0) rc = 1;
        }
    } else {
        rc = run_default_scan(&checked);
    }

    if (rc > 0) {
        printf("\ncheck_observability_pairing: unpaired stderr diagnostics found\n");
        printf("Pair stderr with event_emit/event_emitf, terminal propagation, "
               "or // obs-ok:<reason>.\n");
        return 1;
    }
    if (rc < 0)
        return 2;

    if (checked == 0)
        printf("check_observability_pairing: clean -- no changed app/lib C files\n");
    else
        printf("check_observability_pairing: clean -- stderr diagnostics are "
               "observable or justified\n");
    return 0;
}
