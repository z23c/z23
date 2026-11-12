/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Clear a stale dev-lane auto_reindex_request only after the lane
 *          serves at or above the marker anchor. The dev lane only. */

#include "agent_clear_stale_reindex.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *acr_fallback(const char *value, const char *fallback)
{
    if (value == NULL || value[0] == '\0')
        return fallback;
    return value;
}

static int acr_copy(char *out, size_t cap, const char *text)
{
    size_t n;
    if (text == NULL)
        return -1;
    n = strlen(text);
    if (n + 1 > cap)
        return -1;
    memcpy(out, text, n + 1);
    return 0;
}

static int acr_digits(const char *text, int neg_ok)
{
    if (text == NULL || text[0] == '\0')
        return 0;
    if (neg_ok && text[0] == '-')
        text++;
    if (text[0] < '0' || text[0] > '9')
        return 0;
    while (*text >= '0' && *text <= '9')
        text++;
    return *text == '\0';
}

static int acr_le0(const char *text)
{
    char *end = NULL;
    long long value;
    errno = 0;
    value = strtoll(text, &end, 10);
    if (end == NULL || *end != '\0' || errno == ERANGE)
        return 1;
    return value <= 0;
}

static int acr_below(const char *height, const char *anchor, int *below)
{
    char *end = NULL;
    long long served;
    long long marked;
    errno = 0;
    served = strtoll(height, &end, 10);
    if (end == height || *end != '\0' || errno == ERANGE)
        return -1;
    errno = 0;
    marked = strtoll(anchor, &end, 10);
    if (end == anchor || *end != '\0' || errno == ERANGE)
        return -1;
    *below = served < marked;
    return 0;
}

#if !defined(_WIN32)

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

struct acr_cfg {
    char datadir[4096];
    char marker[4096];
    char cli[4096];
    char port[64];
    char unit[256];
    char timeout_s[32];
    int dry;
    const char *mode;
};

struct acr_out {
    const char *status;
    const char *reason;
    char anchor[128];
    char count[128];
    char height[128];
    char archive[4096];
    int code;
};

static int acr_load(const char *repo, int argc, char **argv, struct acr_cfg *cfg)
{
    const char *datadir;
    const char *home;
    char fallback[4096];
    const char *mode = "text";
    if (argc > 0 && argv != NULL && argv[0] != NULL)
        mode = argv[0];
    cfg->mode = mode;
    cfg->dry = strcmp(acr_fallback(getenv("ZCL_AGENT_CLEAR_STALE_REINDEX_DRY_RUN"), "0"),
                      "1") == 0;
    if (acr_copy(cfg->port, sizeof cfg->port,
                 acr_fallback(getenv("ZCL_AGENT_DEV_RPCPORT"), "18252")) != 0)
        return -1;
    if (acr_copy(cfg->unit, sizeof cfg->unit,
                 acr_fallback(getenv("ZCL_AGENT_DEV_UNIT"), "zcl23-dev.service")) != 0)
        return -1;
    if (acr_copy(cfg->timeout_s, sizeof cfg->timeout_s,
                 acr_fallback(getenv("ZCL_AGENT_CLEAR_STALE_REINDEX_AGENT_TIMEOUT"),
                              "10")) != 0)
        return -1;
    datadir = getenv("ZCL_AGENT_DEV_DATADIR");
    if (datadir == NULL || datadir[0] == '\0') {
        home = getenv("HOME");
        if (home == NULL || home[0] == '\0') {
            fprintf(stderr, "agent-clear-stale-reindex: HOME is unset\n");
            return -2;
        }
        if (snprintf(fallback, sizeof fallback, "%s/.zclassic-c23-dev", home) >=
            (int)sizeof fallback)
            return -1;
        datadir = fallback;
    }
    if (acr_copy(cfg->datadir, sizeof cfg->datadir, datadir) != 0)
        return -1;
    if (snprintf(cfg->marker, sizeof cfg->marker, "%s/auto_reindex_request",
                 cfg->datadir) >= (int)sizeof cfg->marker)
        return -1;
    if (snprintf(cfg->cli, sizeof cfg->cli, "%s/build/bin/zclassic-cli", repo) >=
        (int)sizeof cfg->cli)
        return -1;
    return 0;
}

static int acr_stop(struct acr_out *out, const char *status, const char *reason,
                    int code)
{
    out->status = status;
    out->reason = reason;
    out->code = code;
    return 1;
}

static int acr_words(const char *path, char *anchor, size_t anchor_cap, char *count,
                     size_t count_cap)
{
    FILE *fp = fopen(path, "r");
    char line[256];
    char *cursor;
    char *first;
    char *second;
    if (fp == NULL)
        return -1;
    if (fgets(line, sizeof line, fp) == NULL) {
        fclose(fp);
        return -1;
    }
    if (strchr(line, '\n') == NULL && fgetc(fp) != EOF) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    cursor = line + strspn(line, " \t");
    first = cursor;
    cursor += strcspn(cursor, " \t\r\n");
    if (*cursor != '\0') {
        *cursor = '\0';
        cursor++;
        cursor += strspn(cursor, " \t");
    }
    second = cursor;
    cursor += strcspn(cursor, " \t\r\n");
    *cursor = '\0';
    if (acr_copy(anchor, anchor_cap, first) != 0)
        return -1;
    return acr_copy(count, count_cap, second);
}

static int acr_marker(const struct acr_cfg *cfg, struct acr_out *out)
{
    if (access(cfg->marker, F_OK) != 0)
        return acr_stop(out, "noop", "marker_absent", 0);
    if (access(cfg->marker, R_OK) != 0)
        return acr_stop(out, "refused", "marker_unreadable", 1);
    if (acr_words(cfg->marker, out->anchor, sizeof out->anchor, out->count,
                  sizeof out->count) != 0)
        return acr_stop(out, "refused", "marker_read_failed", 1);
    if (!acr_digits(out->anchor, 1) || !acr_digits(out->count, 1))
        return acr_stop(out, "refused", "marker_malformed", 1);
    if (acr_le0(out->count))
        return acr_stop(out, "noop", "marker_not_pending", 0);
    return 0;
}

static int acr_tmp(char *tmpl, size_t cap)
{
    const char *root = getenv("TMPDIR");
    size_t n;
    static const char tail[] = "/acr-out.XXXXXX";
    if (root == NULL || root[0] == '\0')
        root = "/tmp";
    n = strlen(root);
    if (n + sizeof tail > cap)
        return -1;
    memcpy(tmpl, root, n);
    memcpy(tmpl + n, tail, sizeof tail);
    return mkstemp(tmpl);
}

static int acr_child_io(int fd, int quiet_err)
{
    int sink;
    if (dup2(fd, STDOUT_FILENO) < 0)
        return -1;
    close(fd);
    if (!quiet_err)
        return 0;
    sink = open("/dev/null", O_WRONLY);
    if (sink < 0)
        return -1;
    if (dup2(sink, STDERR_FILENO) < 0) {
        close(sink);
        return -1;
    }
    if (sink > STDERR_FILENO)
        close(sink);
    return 0;
}

static int acr_reap(pid_t child)
{
    int status = 0;
    pid_t got = -1;
    while (got != child) {
        got = waitpid(child, &status, 0);
        if (got == child)
            break;
        if (errno != EINTR)
            return 125;
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return 125;
}

static int acr_snip(const char *path, char *out, size_t cap)
{
    FILE *fp;
    size_t n;
    if (out == NULL || cap < 2)
        return -1;
    fp = fopen(path, "rb");
    if (fp == NULL)
        return -1;
    n = fread(out, 1, cap - 1, fp);
    fclose(fp);
    out[n] = '\0';
    out[strcspn(out, "\r\n")] = '\0';
    return 0;
}

static int acr_spawn(char *const argv[], int quiet_err, char *out, size_t out_cap,
                     char *kept, size_t kept_cap)
{
    char tmpl[1024];
    int fd;
    pid_t child;
    int rc;
    if (kept != NULL && kept_cap > 0)
        kept[0] = '\0';
    fd = acr_tmp(tmpl, sizeof tmpl);
    if (fd < 0)
        return 127;
    fflush(stdout);
    fflush(stderr);
    child = fork();
    if (child < 0) {
        close(fd);
        unlink(tmpl);
        return 127;
    }
    if (child == 0) {
        if (acr_child_io(fd, quiet_err) != 0)
            _exit(127);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fd);
    rc = acr_reap(child);
    if (kept != NULL) {
        if (strlen(tmpl) + 1 > kept_cap) {
            unlink(tmpl);
            return 127;
        }
        memcpy(kept, tmpl, strlen(tmpl) + 1);
        return rc;
    }
    if (out != NULL && acr_snip(tmpl, out, out_cap) != 0)
        rc = 127;
    unlink(tmpl);
    return rc;
}

static int acr_service_up(const struct acr_cfg *cfg)
{
    char active[64];
    char *argv[] = {"systemctl", "--user", "show", (char *)cfg->unit, "-p",
                    "ActiveState", "--value", NULL};
    active[0] = '\0';
    (void)acr_spawn(argv, 1, active, sizeof active, NULL, 0);
    return strcmp(active, "active") == 0;
}

static void acr_height(const struct acr_cfg *cfg, char *out, size_t cap)
{
    char datadir_arg[4120];
    char port_arg[80];
    char *argv[5];
    out[0] = '\0';
    if (snprintf(datadir_arg, sizeof datadir_arg, "-datadir=%s", cfg->datadir) >=
        (int)sizeof datadir_arg)
        return;
    if (snprintf(port_arg, sizeof port_arg, "-rpcport=%s", cfg->port) >=
        (int)sizeof port_arg)
        return;
    argv[0] = (char *)cfg->cli;
    argv[1] = datadir_arg;
    argv[2] = port_arg;
    argv[3] = "getblockcount";
    argv[4] = NULL;
    (void)acr_spawn(argv, 1, out, cap, NULL, 0);
}

static int acr_field(const char *body, const char *key, char *out, size_t cap)
{
    const char *cursor = body;
    size_t key_len;
    if (body == NULL || key == NULL || out == NULL || cap < 6)
        return 0;
    key_len = strlen(key);
    while ((cursor = strchr(cursor, '"')) != NULL) {
        cursor++;
        if (strncmp(cursor, key, key_len) != 0 || cursor[key_len] != '"')
            continue;
        cursor += key_len + 1;
        cursor += strspn(cursor, " \t\n\r");
        if (*cursor != ':')
            continue;
        cursor++;
        cursor += strspn(cursor, " \t\n\r");
        if (strncmp(cursor, "false", 5) == 0) {
            memcpy(out, "false", 6);
            return 1;
        }
        if (strncmp(cursor, "true", 4) == 0) {
            memcpy(out, "true", 5);
            return 1;
        }
    }
    return 0;
}

static void acr_note(const char *text, int *operator_true, int *pack_false,
                     int *work_false)
{
    char word[8];
    if (acr_field(text, "operator_needed", word, sizeof word) &&
        strcmp(word, "true") == 0)
        *operator_true = 1;
    if (acr_field(text, "validation_pack_ok", word, sizeof word) &&
        strcmp(word, "false") == 0)
        *pack_false = 1;
    if (acr_field(text, "agent_work_ready", word, sizeof word) &&
        strcmp(word, "false") == 0)
        *work_false = 1;
}

static int acr_body_ok(const char *path)
{
    FILE *fp;
    char buf[1400];
    char carry[80];
    char window[1600];
    size_t carried = 0;
    int operator_true = 0;
    int pack_false = 0;
    int work_false = 0;
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size <= 0)
        return 0;
    fp = fopen(path, "r");
    if (fp == NULL)
        return 0;
    for (;;) {
        size_t n = fread(buf, 1, sizeof buf, fp);
        size_t total;
        if (n == 0)
            break;
        memcpy(window, carry, carried);
        memcpy(window + carried, buf, n);
        total = carried + n;
        window[total] = '\0';
        acr_note(window, &operator_true, &pack_false, &work_false);
        if (total > sizeof carry) {
            memcpy(carry, window + total - sizeof carry, sizeof carry);
            carried = sizeof carry;
        } else {
            memcpy(carry, window, total);
            carried = total;
        }
    }
    fclose(fp);
    if (operator_true || pack_false || work_false)
        return 0;
    return 1;
}

static int acr_agent_ok(const struct acr_cfg *cfg)
{
    char kept[1024];
    char datadir_arg[4120];
    char port_arg[80];
    char *argv[7];
    int rc;
    int ready;
    if (snprintf(datadir_arg, sizeof datadir_arg, "-datadir=%s", cfg->datadir) >=
        (int)sizeof datadir_arg)
        return 0;
    if (snprintf(port_arg, sizeof port_arg, "-rpcport=%s", cfg->port) >=
        (int)sizeof port_arg)
        return 0;
    argv[0] = "timeout";
    argv[1] = (char *)cfg->timeout_s;
    argv[2] = (char *)cfg->cli;
    argv[3] = datadir_arg;
    argv[4] = port_arg;
    argv[5] = "agent";
    argv[6] = NULL;
    rc = acr_spawn(argv, 1, NULL, 0, kept, sizeof kept);
    if (rc != 0) {
        if (kept[0] != '\0')
            unlink(kept);
        return 0;
    }
    ready = acr_body_ok(kept);
    if (kept[0] != '\0')
        unlink(kept);
    return ready;
}

static int acr_prove(const struct acr_cfg *cfg, struct acr_out *out)
{
    char height[128];
    if (!acr_service_up(cfg))
        return acr_stop(out, "refused", "service_not_active", 1);
    acr_height(cfg, height, sizeof height);
    if (acr_copy(out->height, sizeof out->height, height) != 0)
        return acr_stop(out, "refused", "rpc_height_unavailable", 1);
    if (!acr_digits(height, 0))
        return acr_stop(out, "refused", "rpc_height_unavailable", 1);
    {
        int below = 0;
        if (acr_below(height, out->anchor, &below) != 0 || below)
            return acr_stop(out, "refused", "marker_anchor_above_served_height", 1);
    }
    if (!acr_agent_ok(cfg))
        return acr_stop(out, "refused", "agent_contract_not_ready", 1);
    return 0;
}

static int acr_escape(const char *text, char *out, size_t cap)
{
    size_t used = 0;
    if (text == NULL)
        text = "";
    for (; *text != '\0'; text++) {
        if (*text == '\\' || *text == '"') {
            if (used + 2 >= cap)
                return -1;
            out[used++] = '\\';
        }
        if (used + 1 >= cap)
            return -1;
        out[used++] = *text;
    }
    out[used] = '\0';
    return 0;
}

static int acr_jfield(const char *key, const char *value)
{
    char escaped[8192];
    if (acr_escape(value, escaped, sizeof escaped) != 0)
        return -1;
    printf("  \"%s\": \"%s\",\n", key, escaped);
    return 0;
}

static int acr_json(const struct acr_cfg *cfg, const struct acr_out *out)
{
    const char *keys[] = {
        "schema", "status", "reason", "datadir", "marker", "archive",
        "rpcport", "height", "anchor", "count", NULL};
    const char *values[] = {
        "zcl.agent_dev_reindex_clear.v1", out->status, out->reason, cfg->datadir,
        cfg->marker, out->archive, cfg->port, out->height, out->anchor, out->count};
    int i;
    printf("{\n");
    for (i = 0; keys[i] != NULL; i++) {
        if (acr_jfield(keys[i], values[i]) != 0)
            return 2;
    }
    printf("  \"dry_run\": %s\n", cfg->dry ? "true" : "false");
    printf("}\n");
    return out->code;
}

static void acr_text(const struct acr_out *out)
{
    printf("[agent-clear-stale-reindex] status=%s reason=%s height=%s anchor=%s count=%s\n",
           out->status, out->reason, out->height, out->anchor, out->count);
    if (out->archive[0] != '\0')
        printf("[agent-clear-stale-reindex] archived=%s\n", out->archive);
}

static int acr_finish(const struct acr_cfg *cfg, const struct acr_out *out)
{
    int json = strcmp(cfg->mode, "--json") == 0 || strcmp(cfg->mode, "json") == 0;
    int text = cfg->mode[0] == '\0' || strcmp(cfg->mode, "text") == 0;
    if (!json && !text) {
        fprintf(stderr, "usage: tools/dev/agent-clear-stale-reindex.sh [--json]\n");
        return 2;
    }
    if (json)
        return acr_json(cfg, out);
    acr_text(out);
    return out->code;
}

static int acr_stamp(char *out, size_t cap)
{
    char *argv[] = {"date", "-u", "+%Y%m%dT%H%M%SZ", NULL};
    int rc = acr_spawn(argv, 0, out, cap, NULL, 0);
    if (rc != 0)
        return rc;
    if (out[0] == '\0')
        return 1;
    return 0;
}

static int acr_commit(const struct acr_cfg *cfg, struct acr_out *out)
{
    char stamp[64];
    int rc = acr_stamp(stamp, sizeof stamp);
    if (rc != 0)
        return rc;
    if (snprintf(out->archive, sizeof out->archive, "%s.cleared-%s", cfg->marker,
                 stamp) >= (int)sizeof out->archive)
        return 2;
    out->status = "would_clear";
    out->reason = "stale_marker_proven";
    out->code = 0;
    if (cfg->dry)
        return acr_finish(cfg, out);
    if (rename(cfg->marker, out->archive) != 0)
        return 1;
    out->status = "cleared";
    return acr_finish(cfg, out);
}

static int acr_go(const char *repo, int argc, char **argv)
{
    struct acr_cfg cfg;
    struct acr_out out;
    memset(&out, 0, sizeof out);
    out.status = "";
    out.reason = "";
    {
        int loaded = acr_load(repo, argc, argv, &cfg);
        if (loaded == -2)
            return 1;
        if (loaded != 0) {
            fprintf(stderr, "agent-clear-stale-reindex: path does not fit\n");
            return 2;
        }
    }
    if (acr_marker(&cfg, &out) != 0)
        return acr_finish(&cfg, &out);
    if (acr_prove(&cfg, &out) != 0)
        return acr_finish(&cfg, &out);
    return acr_commit(&cfg, &out);
}

#endif /* !_WIN32 */

int zcl_agent_clear_stale_reindex(const char *repo, int argc, char **argv)
{
#if defined(_WIN32)
    (void)repo;
    (void)argc;
    (void)argv;
    fputs("agent-clear-stale-reindex: unavailable on Windows\n", stdout);
    return 2;
#else
    if (repo == NULL || repo[0] == '\0') {
        fprintf(stderr, "agent-clear-stale-reindex: repo is required\n");
        return 2;
    }
    return acr_go(repo, argc, argv);
#endif
}
