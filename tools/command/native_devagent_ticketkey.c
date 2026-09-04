/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.ticketkey — compute the commuting-ticket key of one
 *          test group at one tip, exactly as docs/agent/COMMUTING_TICKETS.md
 *          specifies, so a push that leaves a group's inputs untouched keeps
 *          that group's ticket valid.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. The push-hook proof is keyed by (commit, base), so any base move
 * invalidates every group's proof even when the move touched nothing that
 * group reads. A ticket keyed by the group's input closure instead survives
 * every push that leaves the closure alone, and only the groups whose
 * closure intersects the diff are re-proved.
 *
 * INPUT (zcl.agent_ticketkey_input.v1)
 *   group    required string. Test group name, e.g. "devagent_situation".
 *   cwd      optional string. Directory to run Git in. Default: the process
 *            working directory.
 *   tip      optional git ref. Default "HEAD".
 *
 * CLOSURE of group G at tip T:
 *   (a) the group's test file tests/harness/src/test_<G>.c;
 *   (b) every source file whose owning group is G, decided by the SAME
 *       in-process shared-rule resolver `code tests` uses
 *       (zcl_native_code_route_for_path over every blob at T);
 *   (c) headers those files include transitively, resolved against the tip
 *       tree: a quoted include first against the includer's directory, then
 *       by basename across the tree. Angle includes are system headers and
 *       are ignored. A vendor/ header is recorded by path only: it joins
 *       the file list but carries no blob line and is never recursed into.
 *   (d) the toolchain epoch (see EPOCH below);
 *   (e) the harness version, constant "ticketkey.v1".
 *
 * KEY. SHA3-256 over the canonical byte string: for each closure path in
 * sorted byte order "<path>:<40-hex git blob hash at T>\n" (a vendor/ path
 * contributes "<path>\n" with no hash), then "epoch:<epoch>\n", then
 * "harness:ticketkey.v1\n", then "group:<group>\n". Rendered 64 lowercase
 * hex.
 *
 * EPOCH. No build-epoch function is callable in-process: the dev build
 * computes its epoch in tools/dev/build-epoch-key.sh at Make time from the
 * compiler identity, profile, flags and build-system fingerprint. This leaf
 * re-derives the same two load-bearing inputs here instead: the first line
 * of `cc --version` plus the CFLAGS logical line from the checkout's
 * Makefile (the line the build documents at Makefile "CFLAGS ="), hashed
 * with SHA3-256. A compiler upgrade or a flag edit therefore moves the key;
 * a source-only edit does not. When `cc` cannot run, the compiler slot is
 * the literal "unavailable" so the leaf still answers deterministically.
 *
 * OUTPUT (zcl.agent_ticketkey.v1) on ok=true
 *   leaf         "dev.agent.ticketkey"
 *   group        the group as given
 *   tip          the tip resolved to 40 lowercase hex
 *   files        sorted array of closure paths (repo-relative)
 *   files_count  number of closure paths
 *   epoch        the toolchain epoch string (64 hex)
 *   harness      "ticketkey.v1"
 *   key          the ticket key (64 hex)
 *   elapsed_ms   wall time inside the handler
 *
 * FAILURE. A missing or empty `group` is ok=false, status "BAD_INPUT". A
 * group with no tests/harness/src/test_<group>.c in the checkout is
 * ok=false, status "UNKNOWN_GROUP". Any Git invocation that does not exit
 * 0, or whose output does not parse, is ok=false, status "GIT_FAILED",
 * with a message naming the failing argv.
 *
 * PROCESS RULE. Run Git and cc only through zcl_spawn_capture() from
 * util/spawn.h. popen(), system() and a shell command string are forbidden
 * and gated.
 */

#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "controllers/agent_impact_rules.h"
#include "json/json.h"
#include "platform/clock.h"
#include "sha3/sha3.h"
#include "util/log_macros.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVT_LEAF "dev.agent.ticketkey"
#define DVT_HARNESS "ticketkey.v1"
#define DVT_TAG "native.devagent.ticketkey"
#define DVT_GIT_TIMEOUT_MS 30000
/* Full-tree `git ls-tree` output (~7500 paths here); fail closed past it. */
#define DVT_TREE_CAP (4u * 1024u * 1024u)
/* One blob's content for include scanning; source blobs are kilobytes. */
#define DVT_BLOB_CAP (8u * 1024u * 1024u)
/* Checkout Makefile read for the CFLAGS logical line. */
#define DVT_MAKEFILE_CAP (1024u * 1024u)

/* Every error return logs context (DEFENSIVE_CODING.md): one choke point so
 * no failure path can forget the log line. */
static void dvt_fail(struct zcl_command_reply *reply,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    LOG_ERROR(DVT_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           phase, false, false, message,
                           evidence ? evidence : "");
}

static const char *dvt_input_str(const struct json_value *input,
                                 const char *key)
{
    const struct json_value *v;
    const char *s;
    if (!input || input->type != JSON_OBJ || !key)
        return NULL;
    v = json_get(input, key);
    if (!v || v->type != JSON_STR)
        return NULL;
    s = json_get_str(v);
    return s && s[0] ? s : NULL;
}

/* Strip trailing newlines (plus a CR when Git is being Windows-polite) so
 * a compared path or SHA is exactly what Git printed. */
static void dvt_strip_newline(char *s)
{
    size_t n;
    if (!s)
        return;
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

static bool dvt_is_hex40(const char *s)
{
    if (!s || strlen(s) != 40)
        return false;
    return strspn(s, "0123456789abcdef") == 40;
}

/* Group names are path-suffixed into tests/harness/src/, so only characters
 * that cannot escape that directory are admittable; anything else names no
 * test file this tree has. */
static bool dvt_group_chars_ok(const char *group)
{
    size_t i;
    if (!group || !group[0] || strlen(group) > 128)
        return false;
    for (i = 0; group[i]; i++) {
        char c = group[i];
        if (!(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9')))
            return false;
    }
    return true;
}

/* Run one Git argv, optionally in `cwd` (NULL runs in the process
 * directory). Returns the exit status; buf holds stdout. Never a shell:
 * argv execs git directly. */
static int dvt_git(const char *cwd, const char *const args[], char *buf,
                   size_t cap)
{
    const char *argv[16];
    size_t n = 0;
    size_t i;
    argv[n++] = "git";
    if (cwd && cwd[0]) {
        argv[n++] = "-C";
        argv[n++] = cwd;
    }
    for (i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return -1;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    return zcl_spawn_capture(argv, buf, cap, DVT_GIT_TIMEOUT_MS);
}

/* `git <args...>` must exit 0 and print one non-empty stripped line that
 * fits `line_cap`. Anything else is a GIT_FAILED naming the argv. */
static bool dvt_git_line(struct zcl_command_reply *reply, const char *cwd,
                         const char *const args[], const char *what,
                         char *line, size_t line_cap)
{
    char argv_text[512];
    char out[8192];
    size_t i;
    int rc;
    argv_text[0] = '\0';
    for (i = 0; args[i]; i++) {
        if (strlen(argv_text) + strlen(args[i]) + 5 < sizeof(argv_text)) {
            if (argv_text[0])
                (void)strcat(argv_text, " ");
            (void)strcat(argv_text, args[i]);
        }
    }
    rc = dvt_git(cwd, args, out, sizeof(out));
    dvt_strip_newline(out);
    if (rc != 0 || out[0] == '\0') {
        char msg[256];
        (void)snprintf(msg, sizeof(msg), "%s failed (exit %d)", what, rc);
        dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute", msg,
                 argv_text);
        return false;
    }
    if (strlen(out) + 1 > line_cap) {
        dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                 "git output did not fit its buffer", argv_text);
        return false;
    }
    (void)memcpy(line, out, strlen(out) + 1);
    return true;
}

struct dvt_blob {
    char *path;
    char hash[41];
};

/* Parse `git ls-tree -r -z <tip>` records ("<mode> SP <type> SP <hash> TAB
 * <path> NUL", `len` bytes of them) into blob rows. Submodules (type
 * commit) and anything that is not a blob carry no file bytes to key and
 * are skipped. */
static bool dvt_parse_tree(struct zcl_command_reply *reply, char *buf,
                           size_t len, struct dvt_blob **blobs, size_t *nblobs)
{
    size_t cap = 0;
    size_t n = 0;
    struct dvt_blob *rows = NULL;
    char *p = buf;
    char *end = buf + len;
    size_t k;
    *blobs = NULL;
    *nblobs = 0;
    while (p < end) {
        char *rec_end = memchr(p, '\0', (size_t)(end - p));
        char *tab;
        char *sp1;
        char *sp2;
        char *hash;
        char *path;
        size_t rec_len = rec_end ? (size_t)(rec_end - p) : (size_t)(end - p);
        if (rec_len == 0) {
            p = rec_end ? rec_end + 1 : end;
            continue;
        }
        tab = memchr(p, '\t', rec_len);
        if (!tab) {
            dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                     "git ls-tree record has no path separator",
                     "git ls-tree -r -z <tip>");
            goto fail;
        }
        *tab = '\0';
        path = tab + 1;
        /* Header is "<mode> SP <type> SP <hash>". */
        sp1 = strchr(p, ' ');
        sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
        if (!sp1 || !sp2) {
            dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                     "git ls-tree record has no mode/type/hash",
                     "git ls-tree -r -z <tip>");
            goto fail;
        }
        if (strncmp(sp1 + 1, "blob ", 5) != 0) {
            p = rec_end ? rec_end + 1 : end;
            continue;
        }
        hash = sp2 + 1;
        if (!dvt_is_hex40(hash) || path[0] == '\0' || path[0] == '/') {
            dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                     "git ls-tree record failed to validate",
                     "git ls-tree -r -z <tip>");
            goto fail;
        }
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 1024;
            struct dvt_blob *nrows =
                zcl_realloc(rows, ncap * sizeof(*nrows), "ticketkey_tree");
            if (!nrows) {
                dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED",
                         "execute", "out of memory reading the tip tree",
                         "git ls-tree -r -z <tip>");
                goto fail;
            }
            rows = nrows;
            cap = ncap;
        }
        rows[n].path = zcl_malloc(strlen(path) + 1, "ticketkey_path");
        if (!rows[n].path) {
            dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                     "out of memory reading the tip tree",
                     "git ls-tree -r -z <tip>");
            goto fail;
        }
        (void)memcpy(rows[n].path, path, strlen(path) + 1);
        (void)memcpy(rows[n].hash, hash, 41);
        n++;
        p = rec_end ? rec_end + 1 : end;
    }
    if (n == 0) {
        free(rows);
        dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                 "git ls-tree listed no blobs at tip",
                 "git ls-tree -r -z <tip>");
        return false;
    }
    *blobs = rows;
    *nblobs = n;
    return true;
fail:
    if (rows) {
        for (k = 0; k < n; k++)
            free(rows[k].path);
        free(rows);
    }
    return false;
}

static int dvt_blob_by_path(const void *a, const void *b)
{
    return strcmp(((const struct dvt_blob *)a)->path,
                  ((const struct dvt_blob *)b)->path);
}

/* Binary search over the path-sorted tree map. */
static const struct dvt_blob *dvt_tree_find(const struct dvt_blob *blobs,
                                            size_t n, const char *path)
{
    size_t lo = 0;
    size_t hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(blobs[mid].path, path);
        if (c == 0)
            return &blobs[mid];
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NULL;
}

/* The router below is a pure function of its path argument (the shared
 * rules are compiled in), but at ~10 ms a path it dominates this leaf: one
 * full-tree pass costs about a minute. This memo keeps the leaf exact while
 * making repeated calls in one process — the test suite, a proof worker
 * keying many groups — pay one pass. Thread-local, so concurrent dispatches
 * never share mutable state; capped, so a long-lived process stops caching
 * instead of growing without bound. */
#define DVT_MEMO_BUCKETS 16384u
#define DVT_MEMO_MAX_ENTRIES 30000u

struct dvt_memo_entry {
    char *path;
    /* Space-joined matched groups (routed verdict first); group names
     * never contain spaces, so splitting is exact. */
    char *groups;
    struct dvt_memo_entry *next;
};

static _Thread_local struct dvt_memo_entry *dvt_memo[DVT_MEMO_BUCKETS];
static _Thread_local size_t dvt_memo_count;

static unsigned long dvt_hash_path(const char *s)
{
    unsigned long h = 5381;
    while (*s)
        h = h * 33 + (unsigned char)*s++;
    return h;
}

static const char *dvt_memo_get(const char *path)
{
    struct dvt_memo_entry *e =
        dvt_memo[dvt_hash_path(path) % DVT_MEMO_BUCKETS];
    while (e) {
        if (strcmp(e->path, path) == 0)
            return e->groups;
        e = e->next;
    }
    return NULL;
}

/* Record the matched groups for `path`. Never fails the caller: when out
 * of memory or past the cap, the path is simply routed again next time. */
static void dvt_memo_put(const char *path, const char *groups)
{
    struct dvt_memo_entry *e;
    unsigned long h;
    if (dvt_memo_count >= DVT_MEMO_MAX_ENTRIES)
        return;
    e = zcl_malloc(sizeof(*e), "ticketkey_memo");
    if (!e)
        return;
    e->path = zcl_malloc(strlen(path) + 1, "ticketkey_memo");
    e->groups = zcl_malloc(strlen(groups) + 1, "ticketkey_memo");
    if (!e->path || !e->groups) {
        free(e->path);
        free(e->groups);
        free(e);
        return;
    }
    (void)memcpy(e->path, path, strlen(path) + 1);
    (void)memcpy(e->groups, groups, strlen(groups) + 1);
    h = dvt_hash_path(path) % DVT_MEMO_BUCKETS;
    e->next = dvt_memo[h];
    dvt_memo[h] = e;
    dvt_memo_count++;
}

/* One candidate name against the group, comparing with and without the
 * test_/spec_ catalog prefix on either side. */
static bool dvt_name_matches_group(const char *cand, const char *group)
{
    if (strcmp(cand, group) == 0)
        return true;
    if (strncmp(cand, "test_", 5) == 0 && strcmp(cand + 5, group) == 0)
        return true;
    if (strncmp(cand, "spec_", 5) == 0 && strcmp(cand + 5, group) == 0)
        return true;
    if (strncmp(group, "test_", 5) == 0 && strcmp(cand, group + 5) == 0)
        return true;
    if (strncmp(group, "spec_", 5) == 0 && strcmp(cand, group + 5) == 0)
        return true;
    return false;
}

/* True when one space-separated group list names G. */
static bool dvt_list_names_group(const char *joined, const char *group)
{
    const char *p = joined;
    while (p && *p) {
        const char *sp;
        size_t len;
        char tok[ZCL_AGENT_IMPACT_GROUP_MAX];
        while (*p == ' ')
            p++;
        if (!*p)
            break;
        sp = strchr(p, ' ');
        len = sp ? (size_t)(sp - p) : strlen(p);
        if (len > 0 && len < sizeof(tok)) {
            (void)memcpy(tok, p, len);
            tok[len] = '\0';
            if (dvt_name_matches_group(tok, group))
                return true;
        }
        p = sp ? sp + 1 : NULL;
    }
    return false;
}

/* True when the router says group G owns `path`: the routed verdict or any
 * matched shared-rule group names G. The memo above makes repeat lookups
 * free; every distinct path is still decided by the shared-rule resolver,
 * never by a copy of its logic. */
static bool dvt_owned_by_group(const char *path, const char *group)
{
    const char *cached = dvt_memo_get(path);
    struct agent_impact_acc acc;
    bool crisk = false;
    const char *routed;
    char joined[32 * ZCL_AGENT_IMPACT_GROUP_MAX + 32];
    size_t pos = 0;
    size_t i;
    if (cached)
        return dvt_list_names_group(cached, group);
    memset(&acc, 0, sizeof(acc));
    routed = zcl_native_code_route_for_path(path, &acc, &crisk);
    joined[0] = '\0';
    if (routed && routed[0]) {
        (void)snprintf(joined + pos, sizeof(joined) - pos, "%s", routed);
        pos = strlen(joined);
    }
    for (i = 0; i < acc.groups_len; i++) {
        if (pos + 1 + strlen(acc.groups[i]) + 1 < sizeof(joined)) {
            if (pos > 0)
                joined[pos++] = ' ';
            (void)snprintf(joined + pos, sizeof(joined) - pos, "%s",
                           acc.groups[i]);
            pos = strlen(joined);
        }
    }
    dvt_memo_put(path, joined);
    return dvt_list_names_group(joined, group);
}

/* Sorted unique closure paths; vendor[i] marks a path-only entry and
 * scanned[i] marks a member whose includes were already walked. */
struct dvt_set {
    char **paths;
    bool *vendor;
    unsigned char *scanned;
    size_t len;
    size_t cap;
};

/* Insert keeping sorted order. A real (hashable) membership beats a vendor
 * path-only mark when both claim one path. */
static bool dvt_set_add(struct dvt_set *set, const char *path, bool vendor)
{
    size_t lo = 0;
    size_t hi = set->len;
    char *copy;
    char **npaths;
    bool *nvendor;
    unsigned char *nscanned;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(set->paths[mid], path);
        if (c == 0) {
            if (set->vendor[mid] && !vendor)
                set->vendor[mid] = false;
            return true;
        }
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (set->len == set->cap) {
        size_t ncap = set->cap ? set->cap * 2 : 64;
        npaths = zcl_realloc(set->paths, ncap * sizeof(*npaths), "ticketkey_set");
        if (!npaths)
            return false;
        set->paths = npaths;
        nvendor =
            zcl_realloc(set->vendor, ncap * sizeof(*nvendor), "ticketkey_set");
        if (!nvendor)
            return false;
        set->vendor = nvendor;
        nscanned = zcl_realloc(set->scanned, ncap * sizeof(*nscanned),
                                   "ticketkey_set");
        if (!nscanned)
            return false;
        set->scanned = nscanned;
        set->cap = ncap;
    }
    copy = zcl_malloc(strlen(path) + 1, "ticketkey_path");
    if (!copy)
        return false;
    (void)memcpy(copy, path, strlen(path) + 1);
    if (lo < set->len) {
        (void)memmove(&set->paths[lo + 1], &set->paths[lo],
                      (set->len - lo) * sizeof(*set->paths));
        (void)memmove(&set->vendor[lo + 1], &set->vendor[lo],
                      (set->len - lo) * sizeof(*set->vendor));
        (void)memmove(&set->scanned[lo + 1], &set->scanned[lo],
                      (set->len - lo) * sizeof(*set->scanned));
    }
    set->paths[lo] = copy;
    set->vendor[lo] = vendor;
    set->scanned[lo] = 0;
    set->len++;
    return true;
}

/* Add one resolved header to the set. Returns false on allocation failure.
 * Vendor/ members join path-only and are never include-scanned. */
static bool dvt_add_header(struct dvt_set *set, const char *path)
{
    return dvt_set_add(set, path,
                       strncmp(path, "vendor/", 7) == 0);
}

/* Scan blob text for #include "header" lines. A quoted name resolves
 * against the includer's directory first, then by basename across the tip
 * tree; every resolution joins the set. Angle includes are system headers
 * and are ignored, as are names that resolve to nothing (generated or
 * otherwise absent at tip). Returns false on allocation failure. */
static bool dvt_scan_includes(const char *content, const char *path,
                              const struct dvt_blob *blobs, size_t nblobs,
                              struct dvt_set *set)
{
    const char *p = content;
    char dir[4096];
    const char *slash = strrchr(path, '/');
    if (slash && (size_t)(slash - path) < sizeof(dir) - 1) {
        (void)memcpy(dir, path, (size_t)(slash - path));
        dir[slash - path] = '\0';
    } else {
        dir[0] = '\0';
    }
    while (p && *p) {
        const char *line_end = strchr(p, '\n');
        size_t line_len = line_end ? (size_t)(line_end - p) : strlen(p);
        const char *q = p;
        while (q < p + line_len && (*q == ' ' || *q == '\t'))
            q++;
        if (q + 8 <= p + line_len && strncmp(q, "#include", 8) == 0) {
            q += 8;
            while (q < p + line_len && (*q == ' ' || *q == '\t'))
                q++;
            if (q < p + line_len && *q == '"') {
                const char *name = q + 1;
                const char *quote =
                    memchr(name, '"', (size_t)((p + line_len) - name));
                if (quote && quote > name) {
                    char header[1024];
                    size_t hlen = (size_t)(quote - name);
                    if (hlen > 0 && hlen < sizeof(header)) {
                        bool resolved = false;
                        size_t k;
                        (void)memcpy(header, name, hlen);
                        header[hlen] = '\0';
                        if (dir[0]) {
                            char cand[4096];
                            size_t dlen = strlen(dir);
                            if (dlen + 1 + hlen < sizeof(cand)) {
                                (void)memcpy(cand, dir, dlen);
                                cand[dlen] = '/';
                                (void)memcpy(cand + dlen + 1, header,
                                             hlen + 1);
                                if (dvt_tree_find(blobs, nblobs, cand)) {
                                    if (!dvt_add_header(set, cand))
                                        return false;
                                    resolved = true;
                                }
                            }
                        } else if (dvt_tree_find(blobs, nblobs, header)) {
                            if (!dvt_add_header(set, header))
                                return false;
                            resolved = true;
                        }
                        if (!resolved) {
                            for (k = 0; k < nblobs; k++) {
                                const char *bp = blobs[k].path;
                                const char *bs = strrchr(bp, '/');
                                const char *base = bs ? bs + 1 : bp;
                                if (strcmp(base, header) == 0) {
                                    if (!dvt_add_header(set, bp))
                                        return false;
                                }
                            }
                        }
                    }
                }
            }
        }
        p = line_end ? line_end + 1 : NULL;
    }
    return true;
}

static bool dvt_scannable(const char *path)
{
    const char *dot = strrchr(path, '.');
    return dot && (strcmp(dot, ".c") == 0 || strcmp(dot, ".h") == 0 ||
                   strcmp(dot, ".inc") == 0 || strcmp(dot, ".def") == 0);
}

static int64_t dvt_elapsed_ms(int64_t t0_ns)
{
    int64_t ms = (clock_now_monotonic_ns() - t0_ns) / 1000000;
    return ms < 0 ? 0 : ms;
}

static void dvt_hex(const unsigned char *bytes, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[2 * i] = digits[(bytes[i] >> 4) & 0xf];
        out[2 * i + 1] = digits[bytes[i] & 0xf];
    }
    out[2 * n] = '\0';
}

/* Toolchain epoch: SHA3-256 over "cc:<first `cc --version` line>\n" plus
 * the CFLAGS logical line from the checkout Makefile. See the EPOCH block
 * in the file contract for why this is re-derived here. */
static bool dvt_epoch(const char *top, char epoch_hex[65])
{
    const char *cc_argv[] = {"cc", "--version", NULL};
    char cc_out[4096];
    char cc_line[1024];
    char make_path[8192];
    FILE *mf = NULL;
    char *make_buf = NULL;
    size_t make_len = 0;
    char cflags[65536];
    char cflags_src[66000];
    struct sha3_256_ctx ctx;
    unsigned char digest[32];
    size_t i;
    int rc = zcl_spawn_capture(cc_argv, cc_out, sizeof(cc_out),
                               DVT_GIT_TIMEOUT_MS);
    if (rc != 0 || cc_out[0] == '\0') {
        (void)snprintf(cc_line, sizeof(cc_line), "unavailable");
    } else {
        char *nl = strchr(cc_out, '\n');
        if (nl)
            *nl = '\0';
        cc_out[sizeof(cc_line) - 1] = '\0';
        (void)snprintf(cc_line, sizeof(cc_line), "%s", cc_out);
    }
    /* The CFLAGS logical line: "CFLAGS = ..." plus \-continuations. */
    cflags[0] = '\0';
    if (strlen(top) + sizeof("/Makefile") < sizeof(make_path)) {
        (void)snprintf(make_path, sizeof(make_path), "%s/Makefile", top);
        mf = fopen(make_path, "rb");
    }
    if (mf) {
        make_buf = zcl_malloc(DVT_MAKEFILE_CAP + 1, "ticketkey_makefile");
        if (make_buf) {
            const char *line;
            make_len = fread(make_buf, 1, DVT_MAKEFILE_CAP, mf);
            make_buf[make_len] = '\0';
            line = make_buf;
            while (line && *line) {
                const char *nl = strchr(line, '\n');
                size_t llen = nl ? (size_t)(nl - line) : strlen(line);
                if (llen >= 9 && strncmp(line, "CFLAGS = ", 9) == 0) {
                    size_t clen = 0;
                    /* Join backslash continuations into one line. */
                    while (line) {
                        const char *le = strchr(line, '\n');
                        size_t ll =
                            le ? (size_t)(le - line) : strlen(line);
                        bool cont = ll > 0 && line[ll - 1] == '\\';
                        size_t take = cont ? ll - 1 : ll;
                        if (clen + take + 1 < sizeof(cflags)) {
                            (void)memcpy(cflags + clen, line, take);
                            clen += take;
                            cflags[clen] = '\0';
                        }
                        if (!le)
                            break;
                        line = le + 1;
                        if (!cont)
                            break;
                    }
                    break;
                }
                line = nl ? nl + 1 : NULL;
            }
            free(make_buf);
        }
        (void)fclose(mf);
    }
    if (cflags[0] == '\0')
        (void)snprintf(cflags, sizeof(cflags), "unavailable");
    (void)snprintf(cflags_src, sizeof(cflags_src), "cc:%s\nmakefile:%s\n",
                   cc_line, cflags);
    /* The continuation join leaves one trailing blank per line; strip
     * trailing blanks so reformatting the Makefile without changing flags
     * keeps the epoch. The compiler line is kept verbatim. */
    for (i = strlen(cflags_src); i > 0; i--) {
        if (cflags_src[i - 1] == ' ' || cflags_src[i - 1] == '\t')
            cflags_src[i - 1] = '\0';
        else
            break;
    }
    (void)strcat(cflags_src, "\n");
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)cflags_src,
                   strlen(cflags_src));
    sha3_256_finalize(&ctx, digest);
    dvt_hex(digest, sizeof(digest), epoch_hex);
    return true;
}

void zcl_native_handle_dev_agent_ticketkey(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    int64_t t0_ns;
    const struct json_value *input;
    const char *group;
    const char *cwd;
    const char *tip_in;
    const char *tip_argv[3];
    char tip[64];
    char top[8192];
    char test_rel[256];
    char test_abs[8448];
    FILE *tf = NULL;
    struct dvt_blob *blobs = NULL;
    size_t nblobs = 0;
    char *tree_buf = NULL;
    struct dvt_set set;
    char epoch_hex[65];
    struct sha3_256_ctx kctx;
    unsigned char kdigest[32];
    char key_hex[65];
    char *blob_buf = NULL;
    size_t i;
    bool progress;
    (void)memset(&set, 0, sizeof(set));

    t0_ns = clock_now_monotonic_ns();
    if (!request || !reply)
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DVT_LEAF);
    input = request->input;

    group = dvt_input_str(input, "group");
    if (!group) {
        dvt_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT", "normalize",
                 "group is required and must be a non-empty string",
                 "dev.agent.ticketkey input keys: group,cwd,tip");
        return;
    }
    cwd = dvt_input_str(input, "cwd");
    tip_in = dvt_input_str(input, "tip");
    if (!tip_in)
        tip_in = "HEAD";

    if (!dvt_group_chars_ok(group)) {
        char msg[256];
        (void)snprintf(msg, sizeof(msg), "no test file for group '%s'",
                       group);
        dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "UNKNOWN_GROUP", "resolve",
                 msg, "tests/harness/src/test_<group>.c");
        return;
    }

    /* Resolve the tip once; everything below is keyed at this commit. */
    tip_argv[0] = "rev-parse";
    tip_argv[1] = tip_in;
    tip_argv[2] = NULL;
    if (!dvt_git_line(reply, cwd, tip_argv, "git rev-parse <tip>", tip,
                      sizeof(tip)))
        return;
    if (!dvt_is_hex40(tip)) {
        dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                 "git rev-parse did not answer a 40-hex commit",
                 "git rev-parse <tip>");
        return;
    }

    /* Checkout top: the test file is addressed from here, so `cwd` may be
     * any directory inside the checkout. */
    {
        const char *top_argv[] = {"rev-parse", "--show-toplevel", NULL};
        if (!dvt_git_line(reply, cwd, top_argv,
                          "git rev-parse --show-toplevel", top, sizeof(top)))
            return;
    }
    if (strlen(group) + 64 >= sizeof(test_rel) ||
        strlen(top) + sizeof(test_rel) >= sizeof(test_abs)) {
        dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "UNKNOWN_GROUP", "resolve",
                 "group name did not fit the test-file path",
                 "tests/harness/src/test_<group>.c");
        return;
    }
    (void)snprintf(test_rel, sizeof(test_rel), "tests/harness/src/test_%s.c",
                   group);
    (void)snprintf(test_abs, sizeof(test_abs), "%s/%s", top, test_rel);
    tf = fopen(test_abs, "rb");
    if (!tf) {
        char msg[256];
        (void)snprintf(msg, sizeof(msg), "no test file for group '%s'",
                       group);
        dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "UNKNOWN_GROUP", "resolve",
                 msg, test_rel);
        return;
    }
    (void)fclose(tf);

    /* One spawn for every blob hash at tip. */
    tree_buf = zcl_malloc(DVT_TREE_CAP, "ticketkey_tree");
    if (!tree_buf) {
        dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                 "out of memory listing the tip tree",
                 "git ls-tree -r -z <tip>");
        return;
    }
    {
        const char *args[] = {"ls-tree", "-r", "-z", tip, NULL};
        size_t span = 0;
        size_t recl;
        int rc = dvt_git(cwd, args, tree_buf, DVT_TREE_CAP);
        if (rc != 0) {
            char msg[128];
            free(tree_buf);
            (void)snprintf(msg, sizeof(msg), "git ls-tree failed (exit %d)",
                           rc);
            dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                     msg, "git ls-tree -r -z <tip>");
            return;
        }
        /* Walk the NUL-separated records. Reaching the cap without
         * finding the end means the tree was truncated: fail closed
         * rather than keying a prefix of the tree. */
        while (span < DVT_TREE_CAP && tree_buf[span] != '\0') {
            recl = strlen(tree_buf + span);
            if (recl == 0)
                break;
            span += recl + 1;
        }
        if (span + 1 >= DVT_TREE_CAP) {
            free(tree_buf);
            dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                     "tip tree did not fit its buffer",
                     "git ls-tree -r -z <tip>");
            return;
        }
        if (!dvt_parse_tree(reply, tree_buf, span, &blobs, &nblobs)) {
            free(tree_buf);
            return;
        }
    }
    free(tree_buf);
    tree_buf = NULL;
    /* ls-tree order follows tree entries, not strict byte order across
     * directories, so sort explicitly for the binary search below. */
    qsort(blobs, nblobs, sizeof(*blobs), dvt_blob_by_path);

    /* (b) every blob the router assigns to this group ... */
    for (i = 0; i < nblobs; i++) {
        if (dvt_owned_by_group(blobs[i].path, group)) {
            if (!dvt_set_add(&set, blobs[i].path, false)) {
                dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED",
                         "execute", "out of memory building the closure",
                         "file->group routing");
                goto cleanup;
            }
        }
    }
    /* ... plus (a) the group's own test file, which the suite compiles. */
    if (!dvt_tree_find(blobs, nblobs, test_rel)) {
        char msg[320];
        (void)snprintf(msg, sizeof(msg),
                       "test file '%s' is not present at tip %s", test_rel,
                       tip);
        dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                 msg, "git ls-tree -r -z <tip>");
        goto cleanup;
    }
    if (!dvt_set_add(&set, test_rel, false)) {
        dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                 "out of memory building the closure", test_rel);
        goto cleanup;
    }

    /* (c) transitive headers: scan every unscanned scannable member until
     * no scan adds a member. Vendor and non-source members join the set
     * but are never scanned. */
    blob_buf = zcl_malloc(DVT_BLOB_CAP, "ticketkey_blob");
    if (!blob_buf) {
        dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                 "out of memory reading blobs", "git show <tip>:<path>");
        goto cleanup;
    }
    do {
        size_t idx = set.len;
        progress = false;
        for (i = 0; i < set.len; i++) {
            if (!set.scanned[i] && !set.vendor[i] &&
                dvt_scannable(set.paths[i])) {
                idx = i;
                break;
            }
        }
        if (idx == set.len)
            break;
        set.scanned[idx] = 1;
        {
            const char *path = set.paths[idx];
            const char *show_argv[3];
            char *ref = NULL;
            size_t reflen = strlen(tip) + 1 + strlen(path) + 1;
            int rc;
            ref = zcl_malloc(reflen, "ticketkey_ref");
            if (!ref) {
                dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED",
                         "execute", "out of memory reading blobs", path);
                goto cleanup;
            }
            (void)snprintf(ref, reflen, "%s:%s", tip, path);
            show_argv[0] = "show";
            show_argv[1] = ref;
            show_argv[2] = NULL;
            rc = dvt_git(cwd, show_argv, blob_buf, DVT_BLOB_CAP);
            free(ref);
            if (rc != 0) {
                char msg[256];
                (void)snprintf(msg, sizeof(msg),
                               "git show failed for '%s' (exit %d)", path,
                               rc);
                dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED",
                         "execute", msg, "git show <tip>:<path>");
                goto cleanup;
            }
            /* spawn NUL-terminates inside the cap: a strlen of cap-1
             * means the blob was truncated, so fail rather than scan a
             * prefix of its includes. */
            if (strlen(blob_buf) + 1 >= DVT_BLOB_CAP) {
                char msg[256];
                (void)snprintf(msg, sizeof(msg),
                               "blob '%s' did not fit its buffer", path);
                dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED",
                         "execute", msg, "git show <tip>:<path>");
                goto cleanup;
            }
        }
        if (!dvt_scan_includes(blob_buf, set.paths[idx], blobs, nblobs,
                               &set)) {
            dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                     "out of memory walking headers", set.paths[idx]);
            goto cleanup;
        }
        progress = true;
    } while (progress);

    /* Epoch, then the key over the canonical bytes. */
    if (!dvt_epoch(top, epoch_hex))
        goto cleanup;
    sha3_256_init(&kctx);
    for (i = 0; i < set.len; i++) {
        const struct dvt_blob *b;
        sha3_256_write(&kctx, (const unsigned char *)set.paths[i],
                       strlen(set.paths[i]));
        if (set.vendor[i]) {
            sha3_256_write(&kctx, (const unsigned char *)"\n", 1);
            continue;
        }
        b = dvt_tree_find(blobs, nblobs, set.paths[i]);
        if (!b) {
            char msg[320];
            (void)snprintf(msg, sizeof(msg),
                           "closure path '%s' left the tip tree mid-walk",
                           set.paths[i]);
            dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "execute",
                     msg, "git ls-tree -r -z <tip>");
            goto cleanup;
        }
        sha3_256_write(&kctx, (const unsigned char *)":", 1);
        sha3_256_write(&kctx, (const unsigned char *)b->hash, 40);
        sha3_256_write(&kctx, (const unsigned char *)"\n", 1);
    }
    {
        char tail[256];
        (void)snprintf(tail, sizeof(tail), "epoch:%s\nharness:%s\ngroup:%s\n",
                       epoch_hex, DVT_HARNESS, group);
        sha3_256_write(&kctx, (const unsigned char *)tail, strlen(tail));
    }
    sha3_256_finalize(&kctx, kdigest);
    dvt_hex(kdigest, sizeof(kdigest), key_hex);

    /* Output. */
    {
        struct json_value files;
        json_init(&files);
        json_set_array(&files);
        for (i = 0; i < set.len; i++) {
            struct json_value item;
            json_init(&item);
            json_set_str(&item, set.paths[i]);
            if (!json_push_back(&files, &item)) {
                json_free(&item);
                json_free(&files);
                dvt_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED",
                         "execute", "out of memory rendering the closure",
                         "files");
                goto cleanup;
            }
            json_free(&item);
        }
        (void)json_push_kv(&reply->data, "files", &files);
        json_free(&files);
    }
    (void)json_push_kv_str(&reply->data, "group", group);
    (void)json_push_kv_str(&reply->data, "tip", tip);
    (void)json_push_kv_int(&reply->data, "files_count", (int64_t)set.len);
    (void)json_push_kv_str(&reply->data, "epoch", epoch_hex);
    (void)json_push_kv_str(&reply->data, "harness", DVT_HARNESS);
    (void)json_push_kv_str(&reply->data, "key", key_hex);
    (void)json_push_kv_int(&reply->data, "elapsed_ms", dvt_elapsed_ms(t0_ns));
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;

cleanup:
    if (blobs) {
        for (i = 0; i < nblobs; i++)
            free(blobs[i].path);
        free(blobs);
    }
    if (set.paths) {
        for (i = 0; i < set.len; i++)
            free(set.paths[i]);
        free(set.paths);
    }
    free(set.vendor);
    free(set.scanned);
    free(blob_buf);
}
