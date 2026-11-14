/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: report existing timing artifacts with explicit coverage limits. */
#define _POSIX_C_SOURCE 200809L
#ifdef ZCL_TIMINGS_STANDALONE
#include "timings.h"
#include <base/safe_alloc.h>
#include <util/spawn.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TIMINGS_MAX (4u * 1024u * 1024u)

static const char *str(const struct json_value *v, const char *key)
{
    const struct json_value *x = json_get(v, key);
    return x && x->type == JSON_STR ? json_get_str(x) : "UNKNOWN";
}
static bool num(const struct json_value *v, const char *key, int64_t *n)
{
    const struct json_value *x = json_get(v, key);
    if (!x || x->type != JSON_INT || x->val.i < 0) return false;
    *n = x->val.i;
    return true;
}
static void field(FILE *f, const struct json_value *v, const char *key)
{
    int64_t n;
    if (num(v, key, &n)) fprintf(f, "%lld", (long long)n);
    else fputs("UNKNOWN", f);
}
static void details(struct timings_context *c, const struct json_value *v,
                    const char *key)
{
    const struct json_value *a = json_get(v, key);
    fputs("         slowest: ", c->out);
    if (!a || a->type != JSON_ARR) { fputs("UNKNOWN\n", c->out); return; }
    for (size_t i = 0; i < a->num_children && i < 3; ++i) {
        const struct json_value *item = json_at(a, i);
        fprintf(c->out, "%s%s ", i ? ", " : "", str(item, "name"));
        field(c->out, item, "ms");
    }
    fputc('\n', c->out);
}
void timings_lint(struct timings_context *c, const struct json_value *v,
                  const char *recency)
{
    int64_t n;
    fprintf(c->out, "lint — make lint\n  %s ", recency);
    field(c->out, v, "wall_ms"); fputs(" ms over ", c->out);
    field(c->out, v, "gate_count"); fputs(" gates at ", c->out);
    field(c->out, v, "jobs"); fprintf(c->out, " jobs [%s]\n", str(v, "generated_at_utc"));
    if (c->lint_total <= 0 || !num(v, "gate_count", &n))
        fputs("  coverage UNKNOWN\n", c->out);
    else if (n < c->lint_total)
        fprintf(c->out, "  PARTIAL %lld of %ld gates\n", (long long)n, c->lint_total);
    details(c, v, "gates");
}
void timings_tests(struct timings_context *c, const struct json_value *v,
                   const char *recency)
{
    int64_t total, ran, cached, skipped;
    fprintf(c->out, "tests — latest runner invocation\n  %s ", recency);
    field(c->out, v, "wall_ms"); fputs(" ms; mode ", c->out);
    fputs(str(v, "mode"), c->out);
    fputs("; jobs ", c->out); field(c->out, v, "jobs");
    fputs("; ran ", c->out); field(c->out, v, "groups_ran");
    fputs("; cached ", c->out); field(c->out, v, "groups_cached");
    fputs("; skipped ", c->out); field(c->out, v, "skipped_count");
    fputs("; total ", c->out); field(c->out, v, "group_count");
    fputs("; failed ", c->out); field(c->out, v, "failed_count");
    fprintf(c->out, " [%s]\n", str(v, "generated_at_utc"));
    if (!num(v, "group_count", &total) || !num(v, "groups_ran", &ran) ||
        !num(v, "groups_cached", &cached) || !num(v, "skipped_count", &skipped))
        fputs("  coverage UNKNOWN\n", c->out);
    else if (skipped || ran > total || cached > total - ran || ran + cached != total)
        fputs("  PARTIAL or inconsistent coverage\n", c->out);
    else fputs("  all recorded groups accounted for (not necessarily executed)\n", c->out);
    details(c, v, "groups");
}
static bool noop(const char *s)
{
    char buf[8]; size_t n = 0;
    for (; *s; ++s) if (!isspace((unsigned char)*s)) {
        if (n == sizeof(buf) - 1) return false;
        buf[n++] = *s;
    }
    buf[n] = 0;
    return !n || !strcmp(buf, ":") || !strcmp(buf, "true");
}
void timings_devloop(struct timings_context *c, const struct json_value *v,
                     const char *recency)
{
    const struct json_value *a = json_get(v, "cases");
    fprintf(c->out, "dev loop — make dev-loop-bench\n  %s [%s]\n", recency, str(v, "generated_at_utc"));
    if (!a || a->type != JSON_ARR) { fputs("  cases UNKNOWN\n", c->out); return; }
    for (size_t i = 0; i < a->num_children; ++i) {
        const struct json_value *item = json_at(a, i);
        const struct json_value *command = json_get(item, "command");
        if (!command || command->type != JSON_STR || noop(json_get_str(command))) {
            fprintf(c->out, "  UNTRUSTED  %s — no timing reported\n", str(item, "name"));
            continue;
        }
        fprintf(c->out, "  ok         %s p50 ", str(item, "name"));
        field(c->out, item, "p50_ms"); fputs(" ms / p95 ", c->out);
        field(c->out, item, "p95_ms"); fprintf(c->out, " ms (%s)\n", json_get_str(command));
    }
}
static bool stages_ok(const struct json_value *a)
{
    if (!a || a->type != JSON_ARR || !a->num_children) return false;
    for (size_t i = 0; i < a->num_children; ++i) {
        int64_t rc;
        if (!num(json_at(a, i), "rc", &rc) || rc) return false;
    }
    return true;
}
void timings_first_build(struct timings_context *c, const struct json_value *v,
                         const char *recency)
{
    const struct json_value *a = json_get(v, "stages");
    fprintf(c->out, "first build — make first-build-timing\n  %s [%s] ",
            recency, str(v, "generated_at_utc"));
    if (!stages_ok(a)) fputs("FAILED or UNKNOWN stage — total withheld\n", c->out);
    else {
        field(c->out, v, "total_seconds"); fputs(" s total on ", c->out);
        field(c->out, v, "cores"); fputs(" cores; peak disk bytes ", c->out);
        field(c->out, v, "peak_disk_bytes"); fputc('\n', c->out);
    }
    if (a && a->type == JSON_ARR) for (size_t i = 0; i < a->num_children; ++i) {
        const struct json_value *item = json_at(a, i); int64_t rc;
        const char *status = !num(item, "rc", &rc) ? "UNKNOWN" : rc ? "FAILED" : "ok";
        fprintf(c->out, "  %-10s %s ", status, str(item, "name"));
        field(c->out, item, "seconds"); fputs(" s\n", c->out);
    }
    if (!strcmp(str(v, "clone_source"), "local"))
        fputs("         clone measured from a LOCAL path; network transfer is extra\n", c->out);
    fprintf(c->out, "         host: %s; load: %s to %s; compiler cache: %s\n",
            str(v, "host"), str(v, "loadavg_start"), str(v, "loadavg_end"),
            str(v, "compiler_cache"));
    fprintf(c->out, "         toolchain: %s\n", str(v, "cc"));
}

static bool read_json(const char *path, struct json_value *v)
{
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    struct stat st;
    if (fd < 0) return false;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); return false; }
    FILE *f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    char *buf = zcl_malloc(TIMINGS_MAX + 1, "timings artifact");
    if (!buf) { fclose(f); return false; }
    size_t n = fread(buf, 1, TIMINGS_MAX + 1, f);
    bool ok = n <= TIMINGS_MAX && !ferror(f) && feof(f);
    if (fclose(f) != 0) ok = false;
    if (ok) ok = json_read(v, buf, n) && v->type == JSON_OBJ;
    free(buf);
    return ok;
}
static int64_t head_epoch(void)
{
    const char *argv[] = {"git", "log", "-1", "--format=%ct", NULL};
    char buf[64], *end;
    if (zcl_spawn_capture(argv, buf, sizeof(buf), 5000) != 0) return 0;
    errno = 0; long long value = strtoll(buf, &end, 10);
    if (errno || end == buf || (*end && *end != '\n') || value <= 0) return 0;
    return value;
}
static const char *recency(const char *path, int64_t head)
{
    struct stat st;
    if (!head || stat(path, &st)) return "TIMESTAMP UNKNOWN";
    return st.st_mtime < head ? "STALE (mtime only)" : "RECENT (mtime only)";
}
typedef void (*section_fn)(struct timings_context *, const struct json_value *, const char *);
static void report_file(struct timings_context *c, const char *cache,
                        const char *rel, section_fn render)
{
    char path[PATH_MAX]; struct json_value v = {0}; struct stat st;
    if (snprintf(path, sizeof(path), "%s/%s", cache, rel) >= (int)sizeof(path)) {
        fprintf(c->out, "  UNKNOWN: artifact path too long: %s\n", rel); return;
    }
    if (stat(path, &st)) { fprintf(c->out, "  NOT MEASURED — no %s\n", path); return; }
    if (!read_json(path, &v)) {
        fprintf(c->out, "  UNKNOWN — unreadable or malformed %s\n", path);
        json_free(&v); return;
    }
    render(c, &v, recency(path, c->head_epoch));
    fprintf(c->out, "         detail: %s\n\n", path);
    json_free(&v);
}
static long lint_count(const char *s)
{
    char *end; errno = 0; long value = strtol(s, &end, 10);
    return !errno && end != s && !*end && value > 0 ? value : 0;
}
static bool write_sample(const char *path, const char *raw)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fputs(raw, f) >= 0;
    if (fclose(f)) ok = false;
    return ok;
}
static bool write_stale_sample(const char *path)
{
    const struct timespec ts[2] = {{1, 0}, {1, 0}};
    return write_sample(path, "{\"gate_count\":1}") && utimensat(AT_FDCWD, path, ts, 0) == 0;
}
static bool file_witness_ok(const char *out)
{
    return out && strstr(out, "NOT MEASURED") && strstr(out, "STALE (mtime only)") &&
           strstr(out, "unreadable or malformed");
}
int timings_file_selftest(void)
{
    char dir[PATH_MAX]; const char *tmp = getenv("TMPDIR");
    char path[PATH_MAX], *out = NULL; size_t len = 0;
    if (!tmp || !*tmp) tmp = "/tmp";
    if (snprintf(dir, sizeof(dir), "%s/z23-timings-XXXXXX", tmp) >= (int)sizeof(dir)) return 1;
    if (!mkdtemp(dir)) return 1;
    if (snprintf(path, sizeof(path), "%s/sample", dir) >= (int)sizeof(path)) return 1;
    FILE *capture = open_memstream(&out, &len);
    if (!capture) { rmdir(dir); return 1; }
    struct timings_context c = {capture, 2, 9};
    report_file(&c, dir, "sample", timings_lint);
    bool ok = write_stale_sample(path);
    if (ok) report_file(&c, dir, "sample", timings_lint);
    if (ok) ok = write_sample(path, "{");
    if (ok) report_file(&c, dir, "sample", timings_lint);
    if (fclose(capture)) ok = false;
    ok = ok && file_witness_ok(out);
    free(out); unlink(path); rmdir(dir);
    return ok ? 0 : 1;
}
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--self-test")) return timings_selftest();
    if (argc > 2 || (argc == 2 && strncmp(argv[1], "--lint-total=", 13))) {
        fputs("usage: timings [--lint-total=N|--self-test]\n", stderr); return 2;
    }
    const char *cache = getenv("ZCL_TIMINGS_CACHE");
    if (!cache || !*cache) cache = ".cache";
    struct timings_context c = {stdout, head_epoch(), argc == 2 ? lint_count(argv[1] + 13) : 0};
    fputs("Timing artifacts (origin and source identity unverified; recency compares mtime with HEAD time only).\n\n", stdout);
    report_file(&c, cache, "lint-timing/last-run.json", timings_lint);
    report_file(&c, cache, "test-timing/last-run.json", timings_tests);
    report_file(&c, cache, "zcl-dev-loop/bench-latest.json", timings_devloop);
    report_file(&c, cache, "first-build-timing/last-run.json", timings_first_build);
    fputs("Incremental build timing is not recorded; time the build directly.\n", stdout);
    return 0;
}
#else
_Static_assert(1, "timings reader is a standalone tool");
#endif
