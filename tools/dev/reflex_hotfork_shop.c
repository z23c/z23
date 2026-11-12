/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Born-green, unrelated-edit, born-red, and exact-revert proof for a
 *          shop view and the zcode work owner. Stages each candidate onto the
 *          owner file, asks dev drive for a bound hotfork story, and restores
 *          both backups. */

#include "reflex_hotfork_shop.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define RHS_FILE 65536
#define RHS_JSON 16384
#define RHS_HEX 80

static const char k_mask[] =
    "git|github|make|shell|sqlite|dht|network|publication|full_link|full_suite";

static const char k_unrelated[] =
    "contexts/market/services/src/market_moderation_service.c";

struct rhs_spec {
    const char *label;
    const char *source_rel;
    const char *output_env;
    const char *output_tail;
    const char *backup_tag;
    const char *stage_tag;
    const char *stamp;
    const char *unrelated_stamp;
    const char *story;
    const char *owner;
    const char *mut_from;
    const char *mut_to;
};

static const struct rhs_spec k_status = {
    "reflex-hotfork-shop-status-acceptance",
    "contexts/market/controllers/src/shop_native_handler.c",
    "ZCL_REFLEX_SHOP_STATUS_ACCEPTANCE_OUTPUT",
    "build/dev-loop/reflex-hotfork-shop-status-acceptance.json",
    "zcl-reflex-shop-status",
    ".reflex-shop-status",
    "ZCL_REFLEX_SHOP_STATUS_ACCEPTANCE",
    "ZCL_REFLEX_SHOP_STATUS_UNRELATED",
    "shop-status-view-contract.v1",
    "contexts/market/controllers/src/shop_native_handler.c",
    "out.gap_count != 5",
    "out.gap_count == 5",
};

static const struct rhs_spec k_reputation = {
    "reflex-hotfork-shop-reputation-acceptance",
    "contexts/market/controllers/src/shop_native_reputation.c",
    "ZCL_REFLEX_SHOP_REPUTATION_ACCEPTANCE_OUTPUT",
    "build/dev-loop/reflex-hotfork-shop-reputation-acceptance.json",
    "zcl-reflex-shop-reputation",
    ".reflex-shop-reputation",
    "ZCL_REFLEX_SHOP_REPUTATION_ACCEPTANCE",
    "ZCL_REFLEX_SHOP_REPUTATION_UNRELATED",
    "shop-reputation-view-contract.v1",
    "contexts/market/controllers/src/shop_native_reputation.c",
    "result.row_count != SHOP_REPUTATION_VIEW_ROW_COUNT",
    "result.row_count == SHOP_REPUTATION_VIEW_ROW_COUNT",
};

static const struct rhs_spec k_zcode = {
    "reflex-hotfork-zcode-work-acceptance",
    "tools/command/native_zcode_work_command.c",
    "ZCL_REFLEX_ZCODE_WORK_ACCEPTANCE_OUTPUT",
    "build/dev-loop/reflex-hotfork-zcode-work-acceptance.json",
    "zcl-reflex-zcode-work",
    ".reflex-zcode-work",
    "ZCL_REFLEX_ZCODE_WORK_ACCEPTANCE",
    "ZCL_REFLEX_ZCODE_WORK_UNRELATED",
    "zcode-work-input-core.v1",
    "tools/command/native_zcode_work_command.c",
    "memcmp(at, part, len) == 0",
    "memcmp(at, part, len) != 0",
};

struct rhs_story {
    char event[32];
    long long feedback_us;
    char object[RHS_HEX];
    char module[RHS_HEX];
    char loaded[RHS_HEX];
    char observation[RHS_HEX];
    char detail[256];
};

struct rhs_cache {
    int hit;
    long long compilers;
    long long linkers;
    char object[RHS_HEX];
    char module[RHS_HEX];
};

struct rhs_job {
    char root[PATH_MAX];
    char bin[PATH_MAX];
    char source[PATH_MAX];
    char unrelated[PATH_MAX];
    char output[PATH_MAX];
    char src_bak[PATH_MAX];
    char un_bak[PATH_MAX];
    char nonce[64];
    long long watcher;
    char session[160];
    long long epoch;
    int have_watcher;
    int armed;
    struct rhs_story green;
    struct rhs_story red;
    struct rhs_story proof;
    struct rhs_story revert;
    struct rhs_cache un_cache;
    struct rhs_cache revert_cache;
};

static const struct rhs_spec *g_spec = &k_status;
static char g_file[RHS_FILE];
static char g_alt[RHS_FILE];
static char g_json[RHS_JSON];
static size_t g_json_n;
static char g_sig_source[PATH_MAX];
static char g_sig_unrelated[PATH_MAX];
static char g_sig_src_bak[PATH_MAX];
static char g_sig_un_bak[PATH_MAX];
static volatile sig_atomic_t g_armed;
static struct sigaction g_old_int;
static struct sigaction g_old_term;
static int g_handlers;

static int rhs_fail(const char *msg)
{
    fprintf(stderr, "%s: %s\n", g_spec->label, msg);
    return 2;
}

static int rhs_fail2(const char *prefix, const char *detail)
{
    fprintf(stderr, "%s: %s%s\n", g_spec->label, prefix, detail);
    return 2;
}

static const char *rhs_env(const char *name)
{
    const char *v = getenv(name);
    if (v == NULL || v[0] == '\0')
        return NULL;
    return v;
}

static int rhs_path(char *out, size_t cap, const char *root, const char *rel)
{
    int n = snprintf(out, cap, "%s/%s", root, rel);
    if (n < 0)
        return -1;
    if ((size_t)n >= cap)
        return -1;
    return 0;
}

static int rhs_regular(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return 0;
    if (S_ISLNK(st.st_mode))
        return 0;
    return S_ISREG(st.st_mode);
}

static int rhs_executable(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    if (!S_ISREG(st.st_mode))
        return 0;
    return access(path, X_OK) == 0;
}

static int rhs_slurp(const char *path, char *buf, size_t cap, size_t *n, mode_t *mode)
{
    struct stat st;
    int fd;
    size_t got = 0;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return -1;
    if ((size_t)st.st_size >= cap)
        return -1;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    while (got < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + got, (size_t)st.st_size - got);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0) {
            close(fd);
            return -1;
        }
        got += (size_t)r;
    }
    close(fd);
    buf[got] = '\0';
    *n = got;
    if (mode != NULL)
        *mode = st.st_mode & 0777;
    return 0;
}

static int rhs_write(const char *path, const char *buf, size_t n, mode_t mode)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    size_t off = 0;
    if (fd < 0)
        return -1;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0) {
            close(fd);
            return -1;
        }
        off += (size_t)w;
    }
    if (fchmod(fd, mode) != 0) {
        close(fd);
        return -1;
    }
    if (close(fd) != 0)
        return -1;
    return 0;
}

static int rhs_copy(const char *from, const char *to)
{
    size_t n = 0;
    mode_t mode = 0644;
    if (rhs_slurp(from, g_alt, sizeof g_alt, &n, &mode) != 0)
        return -1;
    return rhs_write(to, g_alt, n, mode);
}

static int rhs_reap(pid_t child)
{
    int status = 0;
    for (;;) {
        pid_t got = waitpid(child, &status, 0);
        if (got == child)
            break;
        if (errno == EINTR)
            continue;
        return 125;
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 125;
}

static int rhs_exec(char *const argv[], int quiet)
{
    int ends[2];
    pid_t child;
    size_t n = 0;
    g_json_n = 0;
    g_json[0] = '\0';
    if (pipe(ends) != 0)
        return 127;
    child = fork();
    if (child == 0) {
        int sink = -1;
        if (quiet)
            sink = open("/dev/null", O_WRONLY);
        if (sink >= 0) {
            dup2(sink, STDERR_FILENO);
            if (quiet)
                dup2(sink, STDOUT_FILENO);
            close(sink);
        }
        if (!quiet && dup2(ends[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(ends[0]);
        close(ends[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(ends[1]);
    if (child < 0) {
        close(ends[0]);
        return 127;
    }
    while (n + 1 < sizeof g_json) {
        ssize_t r = read(ends[0], g_json + n, sizeof g_json - 1 - n);
        if (r == 0)
            break;
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0) {
            close(ends[0]);
            rhs_reap(child);
            return 127;
        }
        n += (size_t)r;
    }
    g_json[n] = '\0';
    g_json_n = n;
    close(ends[0]);
    {
        int status = rhs_reap(child);
        if (n + 1 >= sizeof g_json)
            return 127;
        return status;
    }
}

static const char *rhs_key(const char *json, size_t n, const char *key)
{
    char pat[80];
    const char *p = json;
    const char *end = json + n;
    int nw = snprintf(pat, sizeof pat, "\"%s\"", key);
    size_t plen;
    if (nw < 0 || (size_t)nw >= sizeof pat)
        return NULL;
    plen = (size_t)nw;
    while (p < end) {
        const char *hit = strstr(p, pat);
        size_t i;
        if (hit == NULL || hit >= end)
            return NULL;
        p = hit + plen;
        i = 0;
        while (p + i < end &&
               (p[i] == ' ' || p[i] == '\t' || p[i] == '\n' || p[i] == '\r'))
            i++;
        if (p + i < end && p[i] == ':')
            return p + i + 1;
    }
    return NULL;
}

static const char *rhs_value(const char *json, size_t n, const char *key)
{
    const char *p = rhs_key(json, n, key);
    const char *end = json + n;
    if (p == NULL)
        return NULL;
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        p++;
    if (p >= end)
        return NULL;
    return p;
}

static int rhs_str(const char *json, size_t n, const char *key, char *out, size_t cap)
{
    const char *p = rhs_value(json, n, key);
    const char *end = json + n;
    size_t i = 0;
    if (p == NULL || *p != '"')
        return -1;
    for (p++; p < end && *p != '"'; p++) {
        char c = *p;
        if (c == '\\' && p + 1 < end) {
            p++;
            c = *p;
        }
        if (i + 1 >= cap)
            return -1;
        out[i++] = c;
    }
    if (p >= end || *p != '"')
        return -1;
    out[i] = '\0';
    return 0;
}

static int rhs_i64(const char *json, size_t n, const char *key, long long *out)
{
    const char *p = rhs_value(json, n, key);
    char buf[32];
    char *end = NULL;
    int i = 0;
    if (p == NULL)
        return -1;
    if (*p == '-' && i + 1 < (int)sizeof buf)
        buf[i++] = *p++;
    if (p == NULL || !isdigit((unsigned char)*p))
        return -1;
    while (isdigit((unsigned char)*p) && i + 1 < (int)sizeof buf)
        buf[i++] = *p++;
    buf[i] = '\0';
    *out = strtoll(buf, &end, 10);
    if (end == buf)
        return -1;
    return 0;
}

static int rhs_lit(const char *json, size_t n, const char *key, const char *lit)
{
    const char *p = rhs_value(json, n, key);
    size_t ln;
    if (p == NULL)
        return 0;
    ln = strlen(lit);
    if (strncmp(p, lit, ln) != 0)
        return 0;
    return p[ln] == ',' || p[ln] == '}' || p[ln] == ']' || p[ln] == ' ' ||
           p[ln] == '\n';
}

static int rhs_eq(const char *json, size_t n, const char *key, const char *want)
{
    char got[256];
    if (rhs_str(json, n, key, got, sizeof got) != 0)
        return 0;
    return strcmp(got, want) == 0;
}

static int rhs_hex64(const char *s)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    if (s == NULL || strlen(s) != 64)
        return 0;
    for (i = 0; i < 64; i++) {
        if (strchr(digits, s[i]) == NULL)
            return 0;
    }
    return 1;
}

static int rhs_copy_roots(const char *json, size_t n, struct rhs_story *s)
{
    if (rhs_str(json, n, "candidate_object_root", s->object, sizeof s->object) != 0)
        return -1;
    if (rhs_str(json, n, "candidate_module_root", s->module, sizeof s->module) != 0)
        return -1;
    if (rhs_str(json, n, "loaded_mapping_root", s->loaded, sizeof s->loaded) != 0)
        return -1;
    if (rhs_str(json, n, "observation_root", s->observation, sizeof s->observation) != 0)
        return -1;
    return 0;
}

static int rhs_story_hex(const char *json, size_t n)
{
    char hex[RHS_HEX];
    if (rhs_str(json, n, "story_root", hex, sizeof hex) != 0 || !rhs_hex64(hex))
        return -1;
    if (rhs_str(json, n, "story_fixture_root", hex, sizeof hex) != 0 || !rhs_hex64(hex))
        return -1;
    return 0;
}

static int rhs_bound_flags(const char *json, size_t n, const char *story)
{
    long long timeout = 0;
    long long us = 0;
    if (!rhs_lit(json, n, "ok", "true"))
        return -1;
    if (!rhs_eq(json, n, "feedback_class", "HOT_FORK"))
        return -1;
    if (!rhs_eq(json, n, "story_fixture_id", story))
        return -1;
    if (!rhs_eq(json, n, "story_adapter", story))
        return -1;
    if (rhs_i64(json, n, "story_timeout_ms", &timeout) != 0 || timeout != 1000)
        return -1;
    if (!rhs_eq(json, n, "forbidden_effect_mask", k_mask))
        return -1;
    if (!rhs_lit(json, n, "candidate_bytes_executed", "true"))
        return -1;
    if (!rhs_lit(json, n, "runtime_published", "false"))
        return -1;
    if (rhs_i64(json, n, "feedback_us", &us) != 0 || us >= 1000000)
        return -1;
    return rhs_story_hex(json, n);
}

static int rhs_bound(const char *json, size_t n, const char *expected,
                     const char *story, struct rhs_story *out)
{
    if (rhs_bound_flags(json, n, story) != 0)
        return -1;
    if (rhs_str(json, n, "event", out->event, sizeof out->event) != 0)
        return -1;
    if (strcmp(out->event, expected) != 0)
        return -1;
    if (rhs_i64(json, n, "feedback_us", &out->feedback_us) != 0)
        return -1;
    if (rhs_copy_roots(json, n, out) != 0)
        return -1;
    if (!rhs_hex64(out->object) || !rhs_hex64(out->module))
        return -1;
    if (!rhs_hex64(out->loaded) || !rhs_hex64(out->observation))
        return -1;
    if (strcmp(out->loaded, out->module) != 0)
        return -1;
    out->detail[0] = '\0';
    (void)rhs_str(json, n, "story_detail", out->detail, sizeof out->detail);
    return 0;
}

static int rhs_dev(struct rhs_job *job, const char *a, const char *b,
                   const char *c, int quiet)
{
    char *argv[6];
    int n = 0;
    argv[n++] = job->bin;
    argv[n++] = "dev";
    if (a != NULL)
        argv[n++] = (char *)a;
    if (b != NULL)
        argv[n++] = (char *)b;
    if (c != NULL)
        argv[n++] = (char *)c;
    argv[n] = NULL;
    return rhs_exec(argv, quiet);
}

static int rhs_begin(struct rhs_job *job)
{
    long long epoch = 0;
    int rc = rhs_dev(job, "begin", NULL, NULL, 0);
    if (rc != 0)
        return rc;
    if (rhs_i64(g_json, g_json_n, "watcher_id", &job->watcher) != 0)
        return rhs_fail("watcher id missing");
    if (rhs_str(g_json, g_json_n, "watcher_session", job->session, sizeof job->session) != 0)
        return rhs_fail("watcher session missing");
    if (rhs_i64(g_json, g_json_n, "epoch", &epoch) != 0)
        return rhs_fail("event cursor missing");
    job->epoch = epoch;
    job->have_watcher = 1;
    return 0;
}

static int rhs_nonce(struct rhs_job *job)
{
    char *argv[] = {"date", "+%s%N", NULL};
    int rc = rhs_exec(argv, 0);
    size_t i;
    if (rc != 0)
        return rc;
    for (i = 0; i < g_json_n; i++) {
        if (g_json[i] == '\n' || g_json[i] == '\r') {
            g_json[i] = '\0';
            break;
        }
    }
    if (g_json[0] == '\0')
        return rhs_fail("nonce missing");
    if (snprintf(job->nonce, sizeof job->nonce, "%s", g_json) >= (int)sizeof job->nonce)
        return rhs_fail("nonce missing");
    return 0;
}

static int rhs_stage(struct rhs_job *job, const char *bytes, size_t n)
{
    char tmp[PATH_MAX];
    mode_t mode = 0644;
    struct stat st;
    int nw;
    if (stat(job->source, &st) == 0)
        mode = st.st_mode & 0777;
    nw = snprintf(tmp, sizeof tmp, "%s/engine/controllers/src/%s.%ld",
                  job->root, g_spec->stage_tag, (long)getpid());
    if (nw < 0 || (size_t)nw >= sizeof tmp)
        return -1;
    if (rhs_write(tmp, bytes, n, mode) != 0)
        return -1;
    if (rename(tmp, job->source) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int rhs_drive_arg(const struct rhs_job *job, int wait, char *arg, size_t cap)
{
    char input[160];
    const char *flag = "false";
    int nw;
    if (wait)
        flag = "true";
    nw = snprintf(input, sizeof input,
                  "{\"after_epoch\":%lld,\"wait_for_edit\":%s,\"timeout_ms\":5000}",
                  job->epoch, flag);
    if (nw < 0 || (size_t)nw >= sizeof input)
        return -1;
    nw = snprintf(arg, cap, "--input=%s", input);
    if (nw < 0 || (size_t)nw >= cap)
        return -1;
    return 0;
}

static int rhs_one_drive(struct rhs_job *job, const char *expected, int wait, int *broke)
{
    char arg[192];
    char event[32];
    long long next = 0;
    int rc;
    *broke = 0;
    if (rhs_drive_arg(job, wait, arg, sizeof arg) != 0)
        return rhs_fail("drive input overflow");
    rc = rhs_dev(job, "drive", arg, NULL, 0);
    if (rc != 0)
        return rc;
    if (rhs_i64(g_json, g_json_n, "epoch", &next) != 0 || next <= job->epoch)
        return rhs_fail2("event cursor did not advance: ", g_json);
    job->epoch = next;
    event[0] = '\0';
    (void)rhs_str(g_json, g_json_n, "event", event, sizeof event);
    if (strcmp(event, expected) == 0 || strcmp(event, "STORY_RED") == 0 ||
        strcmp(event, "COMPILE_RED") == 0)
        *broke = 1;
    return 0;
}

static int rhs_drive(struct rhs_job *job, const char *bytes, size_t n,
                     const char *expected, struct rhs_story *story)
{
    int wait = 1;
    int loops;
    if (rhs_stage(job, bytes, n) != 0)
        return rhs_fail("cannot stage candidate");
    for (loops = 0; loops < 16; loops++) {
        int broke = 0;
        int rc = rhs_one_drive(job, expected, wait, &broke);
        if (rc != 0)
            return rc;
        if (broke)
            break;
        wait = 0;
    }
    if (rhs_bound(g_json, g_json_n, expected, g_spec->story, story) != 0)
        return rhs_fail2("candidate did not return bound ", expected);
    return 0;
}

static int rhs_append_mark(char *buf, size_t *n, size_t cap, const char *mark,
                           const char *nonce)
{
    int w;
    if (*n >= cap)
        return -1;
    w = snprintf(buf + *n, cap - *n, "\n/* %s:%s */\n", mark, nonce);
    if (w < 0 || (size_t)w >= cap - *n)
        return -1;
    *n += (size_t)w;
    return 0;
}

static int rhs_phase_green(struct rhs_job *job, struct rhs_story *story)
{
    size_t n = 0;
    if (rhs_slurp(job->src_bak, g_file, sizeof g_file, &n, NULL) != 0)
        return rhs_fail("cannot read the owner source");
    if (rhs_append_mark(g_file, &n, sizeof g_file, g_spec->stamp, job->nonce) != 0)
        return rhs_fail("cannot stamp the candidate");
    return rhs_drive(job, g_file, n, "STORY_GREEN", story);
}

static int rhs_count(const char *buf, size_t n, const char *needle)
{
    size_t nl = strlen(needle);
    size_t i = 0;
    int count = 0;
    if (nl == 0)
        return 0;
    while (i + nl <= n) {
        if (memcmp(buf + i, needle, nl) == 0) {
            count++;
            i += nl;
        } else {
            i++;
        }
    }
    return count;
}

static int rhs_replace_all(char *buf, size_t *n, const char *from, const char *to)
{
    size_t fl = strlen(from);
    size_t tl = strlen(to);
    size_t i = 0;
    size_t o = 0;
    if (fl == 0)
        return -1;
    while (i < *n) {
        if (i + fl <= *n && memcmp(buf + i, from, fl) == 0) {
            if (o + tl >= sizeof g_alt)
                return -1;
            memcpy(g_alt + o, to, tl);
            o += tl;
            i += fl;
        } else {
            if (o + 1 >= sizeof g_alt)
                return -1;
            g_alt[o++] = buf[i++];
        }
    }
    memcpy(buf, g_alt, o);
    buf[o] = '\0';
    *n = o;
    return 0;
}

static int rhs_unrelated(struct rhs_job *job)
{
    size_t n = 0;
    mode_t mode = 0644;
    int wait = 1;
    int loops;
    char event[32];
    if (rhs_slurp(job->unrelated, g_file, sizeof g_file, &n, &mode) != 0)
        return rhs_fail("cannot read the unrelated source");
    if (rhs_append_mark(g_file, &n, sizeof g_file, g_spec->unrelated_stamp, job->nonce) != 0)
        return rhs_fail("cannot stamp the unrelated source");
    if (rhs_write(job->unrelated, g_file, n, mode) != 0)
        return rhs_fail("cannot stamp the unrelated source");
    for (loops = 0; loops < 16; loops++) {
        char arg[192];
        long long next = 0;
        int rc;
        if (rhs_drive_arg(job, wait, arg, sizeof arg) != 0)
            return rhs_fail("drive input overflow");
        rc = rhs_dev(job, "drive", arg, NULL, 0);
        if (rc != 0)
            return rc;
        if (rhs_i64(g_json, g_json_n, "epoch", &next) != 0 || next <= job->epoch)
            return rhs_fail2("unrelated edit cursor did not advance: ", g_json);
        job->epoch = next;
        event[0] = '\0';
        (void)rhs_str(g_json, g_json_n, "event", event, sizeof event);
        wait = 0;
        if (strcmp(event, "IMPACT_READY") == 0)
            continue;
        break;
    }
    if (!rhs_lit(g_json, g_json_n, "ok", "true"))
        return rhs_fail("unrelated owner was falsely attributed");
    {
        char sid[128];
        sid[0] = '\0';
        (void)rhs_str(g_json, g_json_n, "story_id", sid, sizeof sid);
        if (strcmp(sid, g_spec->story) == 0)
            return rhs_fail("unrelated owner was falsely attributed");
    }
    return 0;
}

static int rhs_phase_red(struct rhs_job *job)
{
    size_t n = 0;
    int hits;
    if (rhs_slurp(job->source, g_file, sizeof g_file, &n, NULL) != 0)
        return rhs_fail("cannot read the staged source");
    if (rhs_replace_all(g_file, &n, g_spec->mut_from, g_spec->mut_to) != 0)
        return rhs_fail("compile-valid semantic mutation was not staged");
    hits = rhs_count(g_file, n, g_spec->mut_to);
    if (hits != 1)
        return rhs_fail("compile-valid semantic mutation was not staged");
    return rhs_drive(job, g_file, n, "STORY_RED", &job->red);
}

static int rhs_wait(struct rhs_job *job, struct rhs_cache *out)
{
    char input[96];
    char arg[128];
    int nw;
    int rc;
    nw = snprintf(input, sizeof input, "{\"after_epoch\":%lld,\"timeout_ms\":100}",
                  job->epoch - 1);
    if (nw < 0 || (size_t)nw >= sizeof input)
        return rhs_fail("wait input overflow");
    nw = snprintf(arg, sizeof arg, "--input=%s", input);
    if (nw < 0 || (size_t)nw >= sizeof arg)
        return rhs_fail("wait input overflow");
    rc = rhs_dev(job, "loop", "wait", arg, 0);
    if (rc != 0)
        return rc;
    out->hit = rhs_lit(g_json, g_json_n, "artifact_cache_hit", "true");
    if (rhs_i64(g_json, g_json_n, "compiler_processes", &out->compilers) != 0)
        out->compilers = -1;
    if (rhs_i64(g_json, g_json_n, "linker_processes", &out->linkers) != 0)
        out->linkers = -1;
    out->object[0] = '\0';
    out->module[0] = '\0';
    (void)rhs_str(g_json, g_json_n, "candidate_object_root", out->object, sizeof out->object);
    (void)rhs_str(g_json, g_json_n, "candidate_module_root", out->module, sizeof out->module);
    return 0;
}

static int rhs_cache_ok(const struct rhs_story *green, const struct rhs_cache *cache)
{
    if (!cache->hit || cache->compilers != 0 || cache->linkers != 0)
        return 0;
    if (strcmp(cache->object, green->object) != 0)
        return 0;
    return strcmp(cache->module, green->module) == 0;
}

static int rhs_mkdir_p(char *dir)
{
    size_t i;
    if (dir[0] == '\0')
        return 0;
    for (i = 1; dir[i] != '\0'; i++) {
        if (dir[i] != '/')
            continue;
        dir[i] = '\0';
        if (mkdir(dir, 0755) != 0 && errno != EEXIST)
            return -1;
        dir[i] = '/';
    }
    if (mkdir(dir, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int rhs_mkdir_parent(const char *file)
{
    char dir[PATH_MAX];
    char *slash;
    if (snprintf(dir, sizeof dir, "%s", file) >= (int)sizeof dir)
        return -1;
    slash = strrchr(dir, '/');
    if (slash == NULL || slash == dir)
        return 0;
    *slash = '\0';
    return rhs_mkdir_p(dir);
}

static int rhs_escape(FILE *fp, const char *s)
{
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            if (fputc('\\', fp) == EOF)
                return -1;
        }
        if (c == '\n') {
            if (fputs("\\n", fp) == EOF)
                return -1;
            continue;
        }
        if (fputc((int)c, fp) == EOF)
            return -1;
    }
    return 0;
}

static const char *rhs_bool(int v)
{
    return v ? "true" : "false";
}

static int rhs_receipt(const struct rhs_job *job)
{
    FILE *fp;
    int same_un_obj = strcmp(job->green.object, job->proof.object) == 0;
    int same_un_mod = strcmp(job->green.module, job->proof.module) == 0;
    int same_re_obj = strcmp(job->green.object, job->revert.object) == 0;
    int same_re_mod = strcmp(job->green.module, job->revert.module) == 0;
    if (rhs_mkdir_parent(job->output) != 0)
        return rhs_fail("cannot create receipt directory");
    fp = fopen(job->output, "w");
    if (fp == NULL)
        return rhs_fail("cannot write receipt");
    if (fprintf(fp,
                "{\n"
                "  \"schema\": \"zcl.reflex_owner_acceptance.v1\",\n"
                "  \"owner\": \"%s\",\n"
                "  \"green\": {\n"
                "    \"event\": \"%s\",\n"
                "    \"feedback_us\": %lld,\n"
                "    \"candidate_object_root\": \"%s\",\n"
                "    \"candidate_module_root\": \"%s\",\n"
                "    \"loaded_mapping_root\": \"%s\",\n"
                "    \"observation_root\": \"%s\"\n"
                "  },\n"
                "  \"born_red\": {\n"
                "    \"event\": \"%s\",\n"
                "    \"feedback_us\": %lld,\n"
                "    \"compile_valid\": true,\n"
                "    \"candidate_bytes_executed\": true,\n"
                "    \"story_detail\": \"",
                g_spec->owner, job->green.event, job->green.feedback_us,
                job->green.object, job->green.module, job->green.loaded,
                job->green.observation, job->red.event, job->red.feedback_us) < 0) {
        fclose(fp);
        return rhs_fail("cannot write receipt");
    }
    if (rhs_escape(fp, job->red.detail) != 0 ||
        fprintf(fp,
                "\",\n"
                "    \"observation_root\": \"%s\"\n"
                "  },\n"
                "  \"unrelated_change\": {\n"
                "    \"false_owner_attribution\": false,\n"
                "    \"artifact_cache_hit\": %s,\n"
                "    \"compiler_processes\": %lld,\n"
                "    \"linker_processes\": %lld,\n"
                "    \"same_object\": %s,\n"
                "    \"same_module\": %s\n"
                "  },\n"
                "  \"exact_revert\": {\n"
                "    \"event\": \"%s\",\n"
                "    \"feedback_us\": %lld,\n"
                "    \"artifact_cache_hit\": %s,\n"
                "    \"compiler_processes\": %lld,\n"
                "    \"linker_processes\": %lld,\n"
                "    \"same_object\": %s,\n"
                "    \"same_module\": %s\n"
                "  },\n"
                "  \"runtime_published\": false\n"
                "}\n",
                job->red.observation, rhs_bool(job->un_cache.hit),
                job->un_cache.compilers, job->un_cache.linkers,
                rhs_bool(same_un_obj), rhs_bool(same_un_mod), job->revert.event,
                job->revert.feedback_us, rhs_bool(job->revert_cache.hit),
                job->revert_cache.compilers, job->revert_cache.linkers,
                rhs_bool(same_re_obj), rhs_bool(same_re_mod)) < 0 ||
        fclose(fp) != 0)
        return rhs_fail("cannot write receipt");
    return 0;
}

static int rhs_stop(struct rhs_job *job)
{
    char input[320];
    char arg[360];
    int nw;
    if (!job->have_watcher)
        return 0;
    nw = snprintf(input, sizeof input,
                  "{\"watcher_id\":%lld,\"watcher_session\":\"%s\"}",
                  job->watcher, job->session);
    if (nw < 0 || (size_t)nw >= sizeof input)
        return rhs_fail("stop input overflow");
    nw = snprintf(arg, sizeof arg, "--input=%s", input);
    if (nw < 0 || (size_t)nw >= sizeof arg)
        return rhs_fail("stop input overflow");
    return rhs_dev(job, "loop", "stop", arg, 1);
}

static int rhs_copy_raw(const char *from, const char *to)
{
    char buf[4096];
    int in = open(from, O_RDONLY);
    int out;
    struct stat st;
    if (in < 0)
        return -1;
    if (fstat(in, &st) != 0) {
        close(in);
        return -1;
    }
    out = open(to, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (out < 0) {
        close(in);
        return -1;
    }
    for (;;) {
        ssize_t r = read(in, buf, sizeof buf);
        size_t off = 0;
        if (r == 0)
            break;
        if (r < 0) {
            close(out);
            close(in);
            return -1;
        }
        while (off < (size_t)r) {
            ssize_t w = write(out, buf + off, (size_t)r - off);
            if (w < 0 && errno == EINTR)
                continue;
            if (w <= 0) {
                close(out);
                close(in);
                return -1;
            }
            off += (size_t)w;
        }
    }
    if (fchmod(out, st.st_mode & 0777) != 0) {
        close(out);
        close(in);
        return -1;
    }
    close(out);
    close(in);
    return 0;
}

static void rhs_on_signal(int sig)
{
    if (g_armed) {
        if (rhs_copy_raw(g_sig_src_bak, g_sig_source) == 0)
            unlink(g_sig_src_bak);
        if (rhs_copy_raw(g_sig_un_bak, g_sig_unrelated) == 0)
            unlink(g_sig_un_bak);
    }
    _exit(128 + (sig & 127));
}

static void rhs_arm(struct rhs_job *job)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = rhs_on_signal;
    sigemptyset(&sa.sa_mask);
    g_handlers = 0;
    if (sigaction(SIGINT, &sa, &g_old_int) == 0)
        g_handlers |= 1;
    if (sigaction(SIGTERM, &sa, &g_old_term) == 0)
        g_handlers |= 2;
    snprintf(g_sig_source, sizeof g_sig_source, "%s", job->source);
    snprintf(g_sig_unrelated, sizeof g_sig_unrelated, "%s", job->unrelated);
    snprintf(g_sig_src_bak, sizeof g_sig_src_bak, "%s", job->src_bak);
    snprintf(g_sig_un_bak, sizeof g_sig_un_bak, "%s", job->un_bak);
    g_armed = 1;
    job->armed = 1;
}

static void rhs_disarm(void)
{
    g_armed = 0;
    if (g_handlers & 1)
        sigaction(SIGINT, &g_old_int, NULL);
    if (g_handlers & 2)
        sigaction(SIGTERM, &g_old_term, NULL);
    g_handlers = 0;
}

static void rhs_restore(struct rhs_job *job)
{
    sigset_t block;
    sigset_t old;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigprocmask(SIG_BLOCK, &block, &old);
    if (job->armed) {
        if (rhs_copy_raw(job->src_bak, job->source) == 0)
            unlink(job->src_bak);
        if (rhs_copy_raw(job->un_bak, job->unrelated) == 0)
            unlink(job->un_bak);
    }
    g_armed = 0;
    job->armed = 0;
    sigprocmask(SIG_SETMASK, &old, NULL);
    job->src_bak[0] = '\0';
    job->un_bak[0] = '\0';
}

static int rhs_backup(struct rhs_job *job)
{
    const char *tmp = rhs_env("TMPDIR");
    int n;
    if (tmp == NULL)
        tmp = "/tmp";
    n = snprintf(job->src_bak, sizeof job->src_bak, "%s/%s.%ld", tmp,
                 g_spec->backup_tag, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof job->src_bak)
        return -1;
    n = snprintf(job->un_bak, sizeof job->un_bak, "%s/%s-unrelated.%ld", tmp,
                 g_spec->backup_tag, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof job->un_bak)
        return -1;
    if (rhs_copy(job->source, job->src_bak) != 0)
        return -1;
    if (rhs_copy(job->unrelated, job->un_bak) != 0)
        return -1;
    return 0;
}

static const char *rhs_output_env(void)
{
    const char *v;
    if (g_spec == &k_reputation)
        v = getenv("ZCL_REFLEX_SHOP_REPUTATION_ACCEPTANCE_OUTPUT");
    else if (g_spec == &k_zcode)
        v = getenv("ZCL_REFLEX_ZCODE_WORK_ACCEPTANCE_OUTPUT");
    else
        v = getenv("ZCL_REFLEX_SHOP_STATUS_ACCEPTANCE_OUTPUT");
    if (v == NULL || v[0] == '\0')
        return NULL;
    return v;
}

static int rhs_locate(struct rhs_job *job)
{
    const char *root = rhs_env("ZCL_SOURCE_ROOT");
    const char *bin = rhs_env("ZCL_DEV_BIN");
    char cwd[PATH_MAX];
    if (root == NULL) {
        if (getcwd(cwd, sizeof cwd) == NULL)
            return rhs_fail("repo is required");
        root = cwd;
    }
    if (snprintf(job->root, sizeof job->root, "%s", root) >= (int)sizeof job->root)
        return rhs_fail("repo is required");
    if (bin == NULL) {
        if (rhs_path(job->bin, sizeof job->bin, job->root, "build/bin/z23-dev") != 0)
            return rhs_fail("missing dev binary: ");
    } else if (snprintf(job->bin, sizeof job->bin, "%s", bin) >= (int)sizeof job->bin) {
        return rhs_fail("missing dev binary: ");
    }
    if (!rhs_executable(job->bin))
        return rhs_fail2("missing dev binary: ", job->bin);
    return 0;
}

static int rhs_outputs(struct rhs_job *job, const char *out)
{
    char dir[PATH_MAX];
    if (rhs_path(job->source, sizeof job->source, job->root, g_spec->source_rel) != 0)
        return rhs_fail("owner source is not a regular file: ");
    if (!rhs_regular(job->source))
        return rhs_fail2("owner source is not a regular file: ", job->source);
    if (rhs_path(job->unrelated, sizeof job->unrelated, job->root, k_unrelated) != 0)
        return rhs_fail("unrelated source is not a regular file: ");
    if (!rhs_regular(job->unrelated))
        return rhs_fail2("unrelated source is not a regular file: ", job->unrelated);
    if (out != NULL) {
        if (snprintf(job->output, sizeof job->output, "%s", out) >= (int)sizeof job->output)
            return rhs_fail("cannot write receipt");
    } else if (rhs_path(job->output, sizeof job->output, job->root, g_spec->output_tail) != 0) {
        return rhs_fail("cannot write receipt");
    }
    if (rhs_path(dir, sizeof dir, job->root, "engine/controllers/src") != 0)
        return rhs_fail("cannot stage candidate");
    if (rhs_mkdir_p(dir) != 0)
        return rhs_fail("cannot stage candidate");
    return rhs_backup(job);
}

static int rhs_prepare(struct rhs_job *job)
{
    int rc = rhs_locate(job);
    if (rc != 0)
        return rc;
    return rhs_outputs(job, rhs_output_env());
}

static int rhs_open(struct rhs_job *job)
{
    int rc = rhs_prepare(job);
    if (rc == 0)
        rhs_arm(job);
    if (rc == 0)
        rc = rhs_begin(job);
    if (rc == 0)
        rc = rhs_nonce(job);
    if (rc == 0)
        rc = rhs_phase_green(job, &job->green);
    if (rc == 0)
        rc = rhs_unrelated(job);
    if (rc == 0)
        rc = rhs_phase_green(job, &job->proof);
    if (rc == 0)
        rc = rhs_wait(job, &job->un_cache);
    if (rc == 0 && !rhs_cache_ok(&job->green, &job->un_cache))
        rc = rhs_fail("exact candidate cache identity was not reused");
    return rc;
}

static int rhs_close(struct rhs_job *job)
{
    int rc = rhs_phase_red(job);
    if (rc == 0)
        rc = rhs_phase_green(job, &job->revert);
    if (rc == 0)
        rc = rhs_wait(job, &job->revert_cache);
    if (rc == 0 && !rhs_cache_ok(&job->green, &job->revert_cache))
        rc = rhs_fail("exact candidate cache identity was not reused");
    if (rc == 0)
        rc = rhs_receipt(job);
    return rc;
}

static int rhs_run(const struct rhs_spec *spec)
{
    struct rhs_job job;
    int rc;
    g_spec = spec;
    memset(&job, 0, sizeof job);
    g_armed = 0;
    rc = rhs_open(&job);
    if (rc == 0)
        rc = rhs_close(&job);
    if (job.have_watcher) {
        int stop = rhs_stop(&job);
        job.have_watcher = 0;
        if (rc == 0)
            rc = stop;
    }
    rhs_restore(&job);
    rhs_disarm();
    if (rc == 0)
        printf("%s: PASS receipt=%s\n", spec->label, job.output);
    g_spec = &k_status;
    return rc;
}

#endif

int zcl_reflex_hotfork_shop_status(void)
{
#if defined(_WIN32)
    fputs("reflex-hotfork-shop-status-acceptance: unavailable on Windows\n", stdout);
    return 2;
#else
    return rhs_run(&k_status);
#endif
}

int zcl_reflex_hotfork_shop_reputation(void)
{
#if defined(_WIN32)
    fputs("reflex-hotfork-shop-reputation-acceptance: unavailable on Windows\n", stdout);
    return 2;
#else
    return rhs_run(&k_reputation);
#endif
}

int zcl_reflex_hotfork_zcode_work(void)
{
#if defined(_WIN32)
    fputs("reflex-hotfork-zcode-work-acceptance: unavailable on Windows\n", stdout);
    return 2;
#else
    return rhs_run(&k_zcode);
#endif
}
