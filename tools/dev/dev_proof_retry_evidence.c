/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Copy bounded first-retry diagnostics before proof cleanup. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "dev_proof_retry_evidence.h"
#include "dev_proof_budget.h"
#include "test_group_catalog.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define RETRY_FILE_LIMIT (1024u * 1024u)
#define RETRY_TOTAL_LIMIT (16u * 1024u * 1024u)
#define RETRY_COUNT_LIMIT 128u
#define RETRY_SCAN_LIMIT (64u * 1024u * 1024u)

#if defined(ZCL_TESTING)
static void (*retry_after_copy_hook)(void *);
static void *retry_after_copy_context;
void zcl_dev_proof_retry_test_after_copy(void (*hook)(void *), void *context)
{
    retry_after_copy_hook = hook; retry_after_copy_context = context;
}
#endif

/* Require a selected catalog spelling, not a substring of another group. */
static bool retry_selected(const char *groups, const char *name)
{
    size_t n = strlen(name);
    if (!n || strspn(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != n)
        return false;
    for (const char *p = groups; p && *p;) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == n && memcmp(p, name, n) == 0) return true;
        p = end ? end + 1 : NULL;
    }
    return false;
}

/* Only the harness's relative basename is accepted; never follow a path from
 * untrusted test output. Require canonical decimal components and suffix. */
static bool retry_index(const char **cursor, size_t *index)
{
    const char *p = *cursor;
    if (*p < '0' || *p > '9') return false;
    if (*p == '0' && p[1] >= '0' && p[1] <= '9') return false;
    *index = 0;
    while (*p >= '0' && *p <= '9') {
        unsigned digit = (unsigned)(*p - '0');
        if (*index > (SIZE_MAX - digit) / 10) return false;
        *index = *index * 10 + digit; ++p;
    }
    *cursor = p; return true;
}

static bool retry_basename(const char *path, const char *group, char name[96])
{
    static const char prefix[] = "./test-tmp/test_parallel_";
    if (strncmp(path, prefix, sizeof(prefix) - 1) != 0) return false;
    const char *p = path + sizeof(prefix) - 1, *begin = p;
    if (*p < '1' || *p > '9') return false;
    while (*p >= '0' && *p <= '9') ++p;
    if (*p++ != '_') return false;
    size_t index = 0;
    if (!retry_index(&p, &index) || strcmp(p, ".log.first") != 0) return false;
    const char *catalog_group = zcl_test_group_catalog_at(index);
    if (!catalog_group || strcmp(catalog_group, group) != 0) return false;
    size_t n = strlen(begin);
    if (n + sizeof("test_parallel_") > 96) return false;
    return snprintf(name, 96, "test_parallel_%s", begin) > 0;
}

static bool retry_open_dir(const char *path, int *fd)
{
    *fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (*fd < 0) return false;
    struct stat st;
    if (fstat(*fd, &st) == 0 && st.st_uid == geteuid() && !(st.st_mode & 0022)) return true;
    close(*fd); *fd = -1; return false;
}

static bool retry_directory_safe(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() && !(st.st_mode & 0022);
}

/* Stat checks are a conservative stability signal, not an atomic snapshot. */
static bool retry_stat_unchanged(const struct stat *before, const struct stat *after)
{
#if defined(__APPLE__)
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino && before->st_size == after->st_size &&
        before->st_mtimespec.tv_sec == after->st_mtimespec.tv_sec && before->st_mtimespec.tv_nsec == after->st_mtimespec.tv_nsec &&
        before->st_ctimespec.tv_sec == after->st_ctimespec.tv_sec && before->st_ctimespec.tv_nsec == after->st_ctimespec.tv_nsec;
#else
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino && before->st_size == after->st_size &&
        before->st_mtim.tv_sec == after->st_mtim.tv_sec && before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
        before->st_ctim.tv_sec == after->st_ctim.tv_sec && before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
#endif
}

static bool retry_write_all(int fd, const char *buf, size_t n, size_t *copied)
{
    while (n) {
        ssize_t written = write(fd, buf, n);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        buf += written; n -= (size_t)written; *copied += (size_t)written;
    }
    return true;
}

struct retry_copy { uint64_t original; size_t copied; bool original_known, truncated, ok, missing; };

static bool retry_copy_bytes(int in, int target, size_t take, size_t *copied)
{
    char buf[8192];
    while (*copied < take) {
        size_t want = take - *copied; if (want > sizeof(buf)) want = sizeof(buf);
        ssize_t got = read(in, buf, want);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0 || !retry_write_all(target, buf, (size_t)got, copied)) return false;
    }
    return true;
}

static struct retry_copy retry_copy_file(int source_dir, const char *source,
                                         int dest_dir, const char *dest,
                                         size_t budget)
{
    struct retry_copy out = {0};
    int in = openat(source_dir, source, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (in < 0) { out.missing = errno == ENOENT; return out; }
    struct stat st;
    if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_size < 0 ||
        st.st_uid != geteuid() || (st.st_mode & 0022)) {
        close(in); return out;
    }
    out.original = (uint64_t)st.st_size;
    out.original_known = true;
    size_t take = out.original > budget ? budget : (size_t)out.original;
    out.truncated = out.original > take;
    int target = openat(dest_dir, dest, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (target < 0) { close(in); return out; }
    bool ok = retry_copy_bytes(in, target, take, &out.copied);
#if defined(ZCL_TESTING)
    if (retry_after_copy_hook) retry_after_copy_hook(retry_after_copy_context);
#endif
    struct stat after;
    if (fstat(in, &after) != 0 || !retry_stat_unchanged(&st, &after)) ok = false;
    if (close(target) != 0) ok = false;
    if (close(in) != 0) ok = false;
    out.ok = ok;
    return out;
}

/* One line comes from the runner parent, but test output can contain arbitrary
 * text too: validate every component before opening anything. */
static bool retry_marker(const char *line, const char *groups, char group[128], char file[96])
{
    char path[192], extra; int used = 0;
    if (sscanf(line, "RETRY-FIRST-PRESERVED %127s first_log=%191s %n%c", group, path, &used, &extra) != 2 || !used)
        return false;
    return retry_selected(groups, group) && retry_basename(path, group, file);
}

struct retry_collector {
    const char *generation, *logs, *groups;
    int gen, source, dest;
    FILE *manifest;
    size_t total;
    bool partial;
    struct zcl_retry_evidence_result result;
};

static bool retry_prepare(struct retry_collector *c)
{
    if (!retry_open_dir(c->generation, &c->gen)) return false;
    c->source = openat(c->gen, "test-tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (c->source < 0 || !retry_directory_safe(c->source) || !retry_open_dir(c->logs, &c->dest)) return false;
    int fd = openat(c->dest, "retry-first.manifest", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    c->manifest = fdopen(fd, "w");
    if (!c->manifest) { close(fd); return false; }
    return true;
}

static void retry_record(struct retry_collector *c, const char *group, const char *file)
{
    char output[40]; (void)snprintf(output, sizeof(output), "retry-first-%03zu.log", c->result.observed);
    size_t left = RETRY_TOTAL_LIMIT - c->total;
    size_t budget = left < RETRY_FILE_LIMIT ? left : RETRY_FILE_LIMIT;
    struct retry_copy copy = retry_copy_file(c->source, file, c->dest, output, budget);
    c->total += copy.copied;
    if (copy.ok) ++c->result.retained;
    else { if (copy.missing) ++c->result.missing; else ++c->result.errors; c->partial = true; }
    if (copy.truncated) c->partial = true;
    char original[32];
    if (copy.original_known) (void)snprintf(original, sizeof(original), "%llu", (unsigned long long)copy.original);
    else (void)snprintf(original, sizeof(original), "unknown");
    if (fprintf(c->manifest, "%s %s original=%s copied=%zu truncated=%d status=%s\n",
                group, output, original, copy.copied, copy.truncated,
                copy.ok ? "retained" : copy.missing ? "missing" : "copy_error") < 0) {
        ++c->result.errors; c->partial = true;
    }
}

static bool retry_line(struct retry_collector *c, const char *line)
{
    char group[128], file[96];
    if (strncmp(line, "RETRY-FIRST-PRESERVE-FAILED ", 28) == 0) {
        if (sscanf(line, "RETRY-FIRST-PRESERVE-FAILED %127s", group) == 1 && retry_selected(c->groups, group)) {
            ++c->result.observed; ++c->result.missing; c->partial = true;
        }
        return true;
    }
    if (strncmp(line, "RETRY-FIRST-PRESERVED ", 22) != 0) return true;
    if (!retry_marker(line, c->groups, group, file)) { ++c->result.errors; c->partial = true; return true; }
    ++c->result.observed;
    if (c->result.observed > RETRY_COUNT_LIMIT) { ++c->result.errors; c->partial = true; return true; }
    if (!c->manifest && !retry_prepare(c)) { ++c->result.errors; c->partial = true; return false; }
    retry_record(c, group, file);
    return true;
}

struct retry_scanner { char line[512]; size_t used; bool discard; };

static bool retry_feed(struct retry_collector *c, struct retry_scanner *s, unsigned char ch)
{
    if (ch == '\0') { ++c->result.errors; c->partial = true; s->discard = true; return true; }
    if (ch == '\n') {
        s->line[s->used] = 0;
        bool ok = s->discard || retry_line(c, s->line);
        s->used = 0; s->discard = false; return ok;
    }
    if (s->discard) return true;
    if (s->used + 1 < sizeof(s->line)) { s->line[s->used++] = (char)ch; return true; }
    s->line[s->used] = 0;
    if (strncmp(s->line, "RETRY-FIRST-", 12) == 0) { ++c->result.errors; c->partial = true; }
    s->discard = true; return true;
}

static void retry_scan(struct retry_collector *c, FILE *in)
{
    size_t scanned = 0; struct retry_scanner state = {0}; unsigned char buf[8192];
    size_t got;
    while ((got = fread(buf, 1, sizeof(buf), in)) != 0) {
        for (size_t i = 0; i < got; i++) {
            if (++scanned > RETRY_SCAN_LIMIT) { ++c->result.errors; c->partial = true; return; }
            if (!retry_feed(c, &state, buf[i])) return;
        }
    }
    if (state.used && !state.discard) { state.line[state.used] = 0; (void)retry_line(c, state.line); }
    if (ferror(in)) { ++c->result.errors; c->partial = true; }
}

static struct zcl_retry_evidence_result retry_finish(struct retry_collector *c, FILE *in)
{
    if (fclose(in) != 0) { ++c->result.errors; c->partial = true; }
    if (c->manifest && fclose(c->manifest) != 0) { ++c->result.errors; c->partial = true; }
    if (c->source >= 0) close(c->source);
    if (c->gen >= 0) close(c->gen);
    if (c->dest >= 0) close(c->dest);
    if (c->result.observed) c->result.status = c->partial ? ZCL_RETRY_EVIDENCE_PARTIAL : ZCL_RETRY_EVIDENCE_COMPLETE;
    else if (c->partial) c->result.status = ZCL_RETRY_EVIDENCE_UNAVAILABLE;
    return c->result;
}

struct zcl_retry_evidence_result zcl_dev_proof_retry_evidence(
    const char *generation, const char *test_log, const char *attempt_logs,
    const char *selected_groups)
{
    struct retry_collector c = { .generation = generation, .logs = attempt_logs,
        .groups = selected_groups, .gen = -1, .source = -1, .dest = -1 };
    if (!generation || !test_log || !attempt_logs || !selected_groups) goto unavailable;
    int log_fd = open(test_log, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (log_fd < 0) goto unavailable;
    if (fstat(log_fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0022)) { close(log_fd); goto unavailable; }
    FILE *in = fdopen(log_fd, "r");
    if (!in) { close(log_fd); goto unavailable; }
    retry_scan(&c, in);
    return retry_finish(&c, in);
unavailable:
    c.result.status = ZCL_RETRY_EVIDENCE_UNAVAILABLE;
    return c.result;
}
#else
struct zcl_retry_evidence_result zcl_dev_proof_retry_evidence(
    const char *generation, const char *test_log, const char *attempt_logs,
    const char *selected_groups)
{
    (void)generation; (void)test_log; (void)attempt_logs; (void)selected_groups;
    return (struct zcl_retry_evidence_result){ .status = ZCL_RETRY_EVIDENCE_UNAVAILABLE };
}
#endif

void zcl_dev_proof_retry_evidence_report(const char *generation, const char *logs,
    const char *key, const char *selected_groups, const char *phases)
{
    char path[4096], note[192];
    struct zcl_retry_evidence_result r = { .status = ZCL_RETRY_EVIDENCE_UNAVAILABLE };
    int n = snprintf(path, sizeof(path), "%s/%s.test.log", logs, key);
    if (n > 0 && (size_t)n < sizeof(path))
        r = zcl_dev_proof_retry_evidence(generation, path, logs, selected_groups);
    const char *status = r.status == ZCL_RETRY_EVIDENCE_NONE ? "none" :
        r.status == ZCL_RETRY_EVIDENCE_COMPLETE ? "complete" :
        r.status == ZCL_RETRY_EVIDENCE_PARTIAL ? "partial" : "unavailable";
    (void)snprintf(note, sizeof(note), "status=%s observed=%zu retained=%zu missing=%zu errors=%zu",
                   status, r.observed, r.retained, r.missing, r.errors);
    if (!zcl_dev_proof_phase_note(phases, "retry_first_evidence", note))
        fprintf(stderr, "proof retry evidence: phase record unavailable (%s)\n", status);
}
