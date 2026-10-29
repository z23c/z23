/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "fleet_probe.h"
#include "zutf8/zutf8.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROBE_HOSTS 16u
#define PROBE_BYTES 16384u
#define BLOCKERS_SHOWN 6u
static const char probe_command[] =
    "echo \"status=$(z23 status 2>/dev/null | head -n 1)\"; "
    "echo \"height=$(z23 getblockcount 2>/dev/null | head -n 1)\"; "
    "echo \"reference=$(zclassic-cli getblockcount 2>/dev/null | head -n 1)\"; "
    "echo \"uptime=$(uptime)\"; "
    "echo \"disk_kb=$(df -Pk \"$HOME\" | awk 'NR==2{print $4}')\"";
static const char blockers_command[] = "z23 core sync blockers 2>/dev/null";

static const struct json_value json_null = {.type = JSON_NULL};
struct probe { pid_t pid; int fd; char output[PROBE_BYTES]; size_t used; int64_t start, end; bool exited; };
static int64_t now_ms(void)
{
    struct timespec ts;
    return clock_gettime(CLOCK_MONOTONIC, &ts) ? -1 : (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static bool host_entry(const char *p, const char *eq, const char *end, struct zapp_fleet_host *host)
{
    size_t label = (size_t)(eq - p), dest = (size_t)(end - eq - 1);
    if (!label || label >= sizeof(host->label) || !dest || dest >= sizeof(host->destination) ||
        strspn(p, "abcdefghijklmnopqrstuvwxyz0123456789-") < label || eq[1] == '-' ||
        strcspn(eq + 1, " \t'\"`$;&|<>\\") < dest) return false;
    memcpy(host->label, p, label); host->label[label] = 0;
    memcpy(host->destination, eq + 1, dest); host->destination[dest] = 0;
    return true;
}
bool zapp_fleet_hosts_parse(const char *spec, struct zapp_fleet_host *hosts, size_t cap, size_t *count)
{
    *count = 0;
    for (const char *p = spec; p && *p && *count < cap;) {
        const char *eq = strchr(p, '='), *end = strchr(p, ',');
        if (!end) end = p + strlen(p);
        if (!eq || eq > end || !host_entry(p, eq, end, &hosts[*count])) return false;
        ++*count; p = *end ? end + 1 : end;
    }
    return *count > 0 && (!spec[0] || *count <= cap);
}
static void line_value(const char *output, const char *key, char *out, size_t cap)
{
    out[0] = 0;
    size_t n = strlen(key);
    for (const char *line = output; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
        if (strncmp(line, key, n) || line[n] != '=') continue;
        size_t w = 0;
        for (const char *v = line + n + 1; *v && *v != '\n' && w + 1 < cap; v++)
            out[w++] = *v >= 0x20 && *v < 0x7f ? *v : '?';
        out[w] = 0; return;
    }
}
static void status_token(const char *status, const char *key, char *out, size_t cap)
{
    out[0] = 0;
    size_t n = strlen(key);
    for (const char *t = status; t && *t; t = strchr(t, ' ') ? strchr(t, ' ') + 1 : NULL)
        if (!strncmp(t, key, n) && t[n] == '=') {
            size_t len = strcspn(t + n + 1, " ");
            snprintf(out, cap, "%.*s", (int)(len < cap ? len : cap - 1), t + n + 1);
            return;
        }
}
static bool push_count(struct json_value *row, const char *key, const char *digits)
{
    if (!digits[0] || strspn(digits, "0123456789") != strlen(digits) || strlen(digits) > 12)
        return json_push_kv(row, key, &json_null);
    return json_push_kv_int(row, key, strtoll(digits, NULL, 10));
}
static void output_value(const char *output, const char *key, char *out, size_t cap)
{
    if (output) line_value(output, key, out, cap); else out[0] = 0;
}
static bool push_status(struct json_value *row, const char *status)
{
    static const char *const keys[] = {"node", "synced", "blocker"};
    char value[160];
    for (size_t i = 0; i < 3; i++) {
        status_token(status, keys[i], value, sizeof(value));
        if (!json_push_kv_str(row, keys[i], value[0] ? value : "unknown")) return false;
    }
    return true;
}
static bool push_load(struct json_value *row, const char *uptime)
{
    const char *load = strstr(uptime, "load average");
    load = load ? strchr(load, ':') : NULL;
    return json_push_kv_real(row, "load1", load ? strtod(load + 1, NULL) : -1.0);
}
static bool push_disk(struct json_value *row, const char *disk)
{
    return strspn(disk, "0123456789") == strlen(disk) && disk[0] ?
        json_push_kv_int(row, "disk_free_gb", strtoll(disk, NULL, 10) / 1048576) :
        json_push_kv(row, "disk_free_gb", &json_null);
}
bool zapp_fleet_row(const char *label, const char *output, int64_t elapsed_ms, struct json_value *row)
{
    char status[512] = "", value[160] = "", uptime[256] = "", disk[32] = "";
    output_value(output, "status", status, sizeof(status));
    output_value(output, "uptime", uptime, sizeof(uptime));
    json_set_object(row);
    bool ok = json_push_kv_str(row, "host", label) &&
        json_push_kv_bool(row, "reachable", output && strstr(output, "status=")) &&
        json_push_kv_int(row, "probe_ms", elapsed_ms) && push_status(row, status);
    output_value(output, "height", value, sizeof(value));
    ok = ok && push_count(row, "height", value);
    output_value(output, "reference", value, sizeof(value));
    ok = ok && push_count(row, "reference_height", value);
    output_value(output, "disk_kb", disk, sizeof(disk));
    return ok && push_load(row, uptime) && push_disk(row, disk);
}
static bool spawn(const struct zapp_fleet_host *host, const char *command, struct probe *p)
{
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC)) return false;
    char *argv[] = {"ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-T", "--",
        (char *)host->destination, (char *)command, NULL};
    p->pid = fork();
    if (p->pid == 0) {
        signal(SIGPIPE, SIG_DFL);
        int nul = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (setpgid(0, 0) || nul < 0 || dup2(nul, 0) < 0 || dup2(pipefd[1], 1) < 0 ||
            dup2(nul, 2) < 0) _exit(127);
        execvp("ssh", argv);
        _exit(127);
    }
    close(pipefd[1]);
    if (p->pid < 0) { close(pipefd[0]); return false; }
    (void)setpgid(p->pid, p->pid);
    p->fd = pipefd[0]; p->start = now_ms();
    return fcntl(p->fd, F_SETFL, O_NONBLOCK) == 0;
}
static void collect(struct probe *p, size_t count, int64_t deadline)
{
    for (size_t live = count; live && now_ms() < deadline;) {
        struct pollfd fds[PROBE_HOSTS];
        for (size_t i = 0; i < count; i++) fds[i] = (struct pollfd){.fd = p[i].fd, .events = POLLIN};
        if (poll(fds, count, 100) < 0 && errno != EINTR) break;
        live = 0;
        for (size_t i = 0; i < count; i++) {
            if (p[i].fd < 0) continue;
            ssize_t n = read(p[i].fd, p[i].output + p[i].used, PROBE_BYTES - 1 - p[i].used);
            if (n > 0) p[i].used += (size_t)n;
            if (n == 0 || p[i].used == PROBE_BYTES - 1 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
                close(p[i].fd); p[i].fd = -1; p[i].end = now_ms();
            } else live++;
        }
    }
}
static void reap(struct probe *p, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (p[i].pid <= 0) continue;
        int status = 0;
        if (p[i].fd >= 0) { (void)kill(-p[i].pid, SIGKILL); close(p[i].fd); p[i].fd = -1; }
        while (waitpid(p[i].pid, &status, 0) < 0 && errno == EINTR) {}
        p[i].exited = p[i].end > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
}
static bool probe_rows(struct probe *p, const struct zapp_fleet_host *hosts, size_t count,
                       int timeout_ms, struct json_value *rows)
{
    struct json_value row = {0};
    bool ok = true;
    for (size_t i = 0; ok && i < count; i++) {
        p[i].output[p[i].used] = 0;
        ok = zapp_fleet_row(hosts[i].label, p[i].exited ? p[i].output : NULL,
            p[i].end > 0 ? p[i].end - p[i].start : timeout_ms, &row) && json_push_back(rows, &row);
        json_free(&row);
    }
    return ok;
}
bool zapp_fleet_probe(const struct zapp_fleet_host *hosts, size_t count, int timeout_ms,
                      char *out, size_t cap)
{
    if (!hosts || !count || count > PROBE_HOSTS || timeout_ms <= 0 || !out || !cap) return false;
    struct probe *p = calloc(count, sizeof(*p));
    if (!p) return false;
    for (size_t i = 0; i < count; i++) { p[i].fd = -1; if (!spawn(&hosts[i], probe_command, &p[i])) p[i].pid = -1; }
    int64_t start = now_ms();
    collect(p, count, start + timeout_ms);
    reap(p, count);
    struct json_value root = {0}, rows = {0};
    json_set_object(&root); json_set_array(&rows);
    bool ok = start >= 0 && probe_rows(p, hosts, count, timeout_ms, &rows);
    ok = ok && json_push_kv(&root, "hosts", &rows) &&
        json_push_kv_int(&root, "observed_at", (int64_t)time(NULL)) && json_write(&root, out, cap) < cap;
    json_free(&rows); json_free(&root); free(p);
    return ok;
}
static bool blocker_rows(const struct json_value *items, struct json_value *list)
{
    bool ok = true;
    for (size_t i = 0; ok && i < json_size(items) && i < BLOCKERS_SHOWN; i++) {
        const struct json_value *item = json_at(items, i);
        const char *id = json_get_str(json_get(item, "id")), *kind = json_get_str(json_get(item, "class")),
            *reason = json_get_str(json_get(item, "reason"));
        if (!id[0]) continue;
        struct json_value row = {0}; json_set_object(&row);
        ok = json_push_kv_str(&row, "id", id) && json_push_kv_str(&row, "class", kind[0] ? kind : "unknown") &&
            json_push_kv_str(&row, "reason", reason) && json_push_back(list, &row);
        json_free(&row);
    }
    return ok;
}
static const char *blockers_error(const struct json_value *doc, bool parsed, const char *output)
{
    const char *message = json_get_str(json_get(json_get(doc, "error"), "message"));
    if (!output) return "The host did not answer.";
    if (!parsed) return "The host's blocker report could not be read.";
    return message[0] && strlen(message) < 400 ? message : "The host reported no blocker list.";
}
bool zapp_fleet_blockers_summary(const char *label, const char *output, char *out, size_t cap)
{
    struct json_value doc = {0}, root = {0}, list = {0};
    bool parsed = output && zutf8_validate(output) && json_read(&doc, output, strlen(output));
    const struct json_value *data = json_get(&doc, "data"), *items = json_get(data, "blockers");
    json_set_object(&root); json_set_array(&list);
    bool ok = json_push_kv_str(&root, "host", label);
    if (parsed && items && json_get_bool(json_get(&doc, "ok")))
        ok = ok && json_push_kv_int(&root, "active", json_get_int(json_get(data, "active_count"))) &&
            blocker_rows(items, &list) && json_push_kv(&root, "blockers", &list);
    else ok = ok && json_push_kv_str(&root, "error", blockers_error(&doc, parsed, output));
    ok = ok && json_write(&root, out, cap) < cap;
    json_cleanse_strings(&doc); json_free(&doc); json_free(&list); json_free(&root);
    return ok;
}
bool zapp_fleet_blockers(const struct zapp_fleet_host *host, int timeout_ms, char *out, size_t cap)
{
    if (!host || timeout_ms <= 0 || !out || !cap) return false;
    struct probe *p = calloc(1, sizeof(*p));
    if (!p) return false;
    p->fd = -1;
    if (!spawn(host, blockers_command, p)) p->pid = -1;
    collect(p, 1, now_ms() + timeout_ms);
    reap(p, 1);
    p->output[p->used] = 0;
    bool ok = zapp_fleet_blockers_summary(host->label, p->end > 0 && p->used ? p->output : NULL, out, cap);
    free(p);
    return ok;
}
const char zapp_fleet_tool_guide[] = "The fleet observations show at most one blocker for each host and never "
    "the rest. Whenever a question asks about a host's blockers or problems, or why it is blocked, "
    "call host_blockers for that host before answering. Only an operator on that host can clear its "
    "blockers; no control in this app clears them, so never suggest one for a blocker.";
bool zapp_fleet_tool_schema(const struct zapp_fleet_host *hosts, size_t count, struct json_value *schema)
{
    char labels[PROBE_HOSTS * 20] = "", text[2048];
    size_t used = 0;
    for (size_t i = 0; i < count && i < PROBE_HOSTS; i++)
        used += (size_t)snprintf(labels + used, sizeof(labels) - used, "%s\"%s\"", i ? "," : "", hosts[i].label);
    int n = snprintf(text, sizeof(text), "[{\"type\":\"function\",\"function\":{\"name\":\"host_blockers\","
        "\"description\":\"Read the current sync blockers of one fleet host with each blocker's reason. "
        "Read-only; use it when the observations do not answer the question.\",\"parameters\":"
        "{\"type\":\"object\",\"properties\":{\"host\":{\"type\":\"string\",\"enum\":[%s]}},"
        "\"required\":[\"host\"]}}}]", labels);
    return count && n > 0 && (size_t)n < sizeof(text) && json_read(schema, text, (size_t)n);
}
const struct zapp_fleet_host *zapp_fleet_tool_host(const struct zapp_fleet_host *hosts, size_t count,
                                                   const char *name, const char *arguments)
{
    struct json_value args = {0};
    const char *label = name && !strcmp(name, "host_blockers") && arguments &&
        json_read(&args, arguments, strlen(arguments)) ? json_get_str(json_get(&args, "host")) : NULL;
    const struct zapp_fleet_host *host = NULL;
    for (size_t i = 0; label && !host && i < count; i++)
        if (!strcasecmp(hosts[i].label, label)) host = &hosts[i];
    json_free(&args);
    return host;
}
static bool mentions(const char *text, const char *word)
{
    size_t n = strlen(word);
    for (const char *at = strcasestr(text, word); at; at = strcasestr(at + 1, word))
        if ((at == text || !isalnum((unsigned char)at[-1])) && !isalnum((unsigned char)at[n])) return true;
    return false;
}
/* A label is heard as written ("r1", "r 1") or with its last digit spoken ("r one"). */
static bool mentions_label(const char *text, const char *label)
{
    static const char *const digits[] = {"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"};
    size_t n = strlen(label);
    char spaced[24], spoken[32];
    if (mentions(text, label)) return true;
    if (n < 2 || !isdigit((unsigned char)label[n - 1])) return false;
    snprintf(spaced, sizeof(spaced), "%.*s %c", (int)(n - 1), label, label[n - 1]);
    snprintf(spoken, sizeof(spoken), "%.*s %s", (int)(n - 1), label, digits[label[n - 1] - '0']);
    return mentions(text, spaced) || mentions(text, spoken);
}
const char *zapp_prompt_question(const char *prompt)
{
    const char *question = prompt;
    for (const char *at = prompt ? strstr(prompt, "Question: ") : NULL; at; at = strstr(at + 1, "Question: "))
        question = at + 10;
    return question;
}
bool zapp_fleet_tool_wanted(const struct zapp_fleet_host *hosts, size_t count, const char *prompt,
                            char *name, size_t name_cap, char *arguments, size_t arguments_cap)
{
    static const char *const asks[] = {"blocker", "blocked", "blocking", "wrong", "problem", "issue", "stuck"};
    const char *question = zapp_prompt_question(prompt);
    const struct zapp_fleet_host *named = NULL;
    bool asked = false;
    for (size_t i = 0; question && !asked && i < sizeof(asks) / sizeof(asks[0]); i++)
        asked = strcasestr(question, asks[i]);
    for (size_t i = 0; asked && !named && i < count; i++)
        if (mentions_label(question, hosts[i].label)) named = &hosts[i];
    return named && snprintf(name, name_cap, "host_blockers") < (int)name_cap &&
        snprintf(arguments, arguments_cap, "{\"host\":\"%s\"}", named->label) < (int)arguments_cap;
}
