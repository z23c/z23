/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Node-log controller for the native `getnodelog` primitive.
 *
 * Reverse-scans <datadir>/node.log in 64 KB chunks, matches each line
 * against a POSIX-extended regex, filters by level, and stops at
 * `max_lines` or the scan-byte cap. Bounded memory (one chunk plus an
 * accumulator) so it is cheaper than reading the whole multi-MB log.
 *
 * Level detection: log lines from LOG_FAIL / LOG_ERR / LOG_NULL all
 * start with `[domain] file:line function(): message` where `domain`
 * is e.g. "validation", "sync", "net". This handler also recognises
 * the leading `[FATAL]` / `[WARN]` markers used by some boot-time
 * printf paths.
 */

#include "platform/time_compat.h"
#include "controllers/diagnostics_internal.h"

#include "json/json.h"
#include "rpc/server.h"
#include "controllers/strong_params.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#define NODELOG_DEFAULT_SINCE_SECS    300
#define NODELOG_MAX_SINCE_SECS       86400
#define NODELOG_DEFAULT_MAX_LINES      50
#define NODELOG_MAX_MAX_LINES         500
#define NODELOG_CHUNK_SIZE           65536
#define NODELOG_MAX_PATTERN_LEN        256
#define NODELOG_MAX_SCAN_BYTES   (16 * 1024 * 1024) /* 16 MB hard cap */

enum log_level { LL_ALL = 0, LL_INFO, LL_WARN, LL_ERROR, LL_FATAL };

static bool digit2(const char *s, int *out)
{
    if (!s || s[0] < '0' || s[0] > '9' ||
        s[1] < '0' || s[1] > '9')
        return false;
    *out = (s[0] - '0') * 10 + (s[1] - '0');
    return true;
}

static bool digit4(const char *s, int *out)
{
    int hi = 0, lo = 0;
    if (!digit2(s, &hi) || !digit2(s + 2, &lo))
        return false; // raw-return-ok:format-probe-not-a-mismatch-error
    *out = hi * 100 + lo;
    return true;
}

static bool leap_year(int year)
{
    return (year % 4 == 0) && ((year % 100 != 0) || (year % 400 == 0));
}

static int month_days(int year, int month)
{
    static const int k_days[] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    if (month < 1 || month > 12) return 0;
    if (month == 2 && leap_year(year)) return 29;
    return k_days[month - 1];
}

static bool make_unix_utc(int year, int month, int day,
                          int hour, int minute, int second,
                          int64_t *out)
{
    if (!out || year < 1970 || month < 1 || month > 12 ||
        day < 1 || day > month_days(year, month) ||
        hour < 0 || hour > 23 || minute < 0 || minute > 59 ||
        second < 0 || second > 60)
        return false;

    int y = year - (month <= 2);
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (unsigned)((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5
                                    + day - 1);
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    int64_t days = (int64_t)era * 146097 + (int64_t)doe - 719468;
    *out = days * 86400 + hour * 3600 + minute * 60 + second;
    return true;
}

static int current_utc_year(int64_t now)
{
    time_t t = (time_t)now;
    struct tm tmv;
    if (!gmtime_r(&t, &tmv))
        return 1970;
    return tmv.tm_year + 1900;
}

static bool make_unix_current_year(int year, int month, int day,
                                   int hour, int minute, int second,
                                   int64_t now, int64_t *out)
{
    if (!make_unix_utc(year, month, day, hour, minute, second, out))
        return false; // raw-return-ok:invalid-calendar-date-not-a-mismatch-error

    if (*out > now + 86400 &&
        make_unix_utc(year - 1, month, day, hour, minute, second, out))
        return true;
    return true;
}

static bool parse_iso_timestamp(const char *s, int64_t *out)
{
    if (!s || strlen(s) < 19)
        return false;

    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (!digit4(s, &year) || s[4] != '-' ||
        !digit2(s + 5, &month) || s[7] != '-' ||
        !digit2(s + 8, &day) || (s[10] != 'T' && s[10] != ' ') ||
        !digit2(s + 11, &hour) || s[13] != ':' ||
        !digit2(s + 14, &minute) || s[16] != ':' ||
        !digit2(s + 17, &second))
        return false;

    return make_unix_utc(year, month, day, hour, minute, second, out);
}

static int parse_month3(const char *s)
{
    static const char *const k_months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    if (!s) return 0;
    for (int i = 0; i < 12; i++) {
        if (s[0] == k_months[i][0] &&
            s[1] == k_months[i][1] &&
            s[2] == k_months[i][2])
            return i + 1;
    }
    return 0;
}

static bool parse_mmdd_timestamp(const char *s, int64_t now, int64_t *out)
{
    if (!s || strlen(s) < 14)
        return false;

    int month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (!digit2(s, &month) || s[2] != '-' ||
        !digit2(s + 3, &day) || s[5] != ' ' ||
        !digit2(s + 6, &hour) || s[8] != ':' ||
        !digit2(s + 9, &minute) || s[11] != ':' ||
        !digit2(s + 12, &second))
        return false;

    return make_unix_current_year(current_utc_year(now), month, day,
                                  hour, minute, second, now, out);
}

static bool parse_syslog_timestamp(const char *s, int64_t now, int64_t *out)
{
    if (!s || strlen(s) < 15)
        return false;

    int month = parse_month3(s);
    if (month == 0 || s[3] != ' ')
        return false;

    const char *p = s + 4;
    if (*p == ' ') p++;
    if (*p < '0' || *p > '9') return false;
    int day = *p++ - '0';
    if (*p >= '0' && *p <= '9')
        day = day * 10 + (*p++ - '0');
    if (*p++ != ' ') return false;

    int hour = 0, minute = 0, second = 0;
    if (!digit2(p, &hour) || p[2] != ':' ||
        !digit2(p + 3, &minute) || p[5] != ':' ||
        !digit2(p + 6, &second))
        return false;

    return make_unix_current_year(current_utc_year(now), month, day,
                                  hour, minute, second, now, out);
}

static bool line_timestamp_unix(const char *line, int64_t now, int64_t *out)
{
    if (!line || !out) return false;

    const char *json_ts = strstr(line, "\"ts\":\"");
    if (json_ts && parse_iso_timestamp(json_ts + 6, out))
        return true;

    if (parse_iso_timestamp(line, out))
        return true;
    if (parse_mmdd_timestamp(line, now, out))
        return true;
    if (parse_syslog_timestamp(line, now, out))
        return true;
    return false;
}

/* Case-insensitive; returns -1 for an unknown token so the caller can
 * reject it loudly — an unknown level silently meaning "all" made
 * `level=WARN` return unfiltered lines with no hint the filter was
 * ignored. */
static int parse_level(const char *s)
{
    if (!s) return LL_ALL;
    if (!strcasecmp(s, "all"))   return LL_ALL;
    if (!strcasecmp(s, "info"))  return LL_INFO;
    if (!strcasecmp(s, "warn"))  return LL_WARN;
    if (!strcasecmp(s, "error")) return LL_ERROR;
    if (!strcasecmp(s, "fatal")) return LL_FATAL;
    return -1; // raw-return-ok:sentinel for unknown token; caller rejects with a logged string error
}

static enum log_level line_level(const char *line)
{
    /* Current LOG_* format (zcl_log_emit_at, log_level.c):
     *   YYYY-MM-DDTHH:MM:SSZ LEVEL [domain] file:line func(): msg
     * The level token sits positionally right after the 20-char
     * timestamp + one space — parse it exactly, no text sniffing. */
    if (line) {
        int64_t ts = 0;
        if (parse_iso_timestamp(line, &ts) &&
            line[19] == 'Z' && line[20] == ' ') {
            const char *p = line + 21;
            if (!strncmp(p, "FATAL ", 6)) return LL_FATAL;
            if (!strncmp(p, "ERROR ", 6)) return LL_ERROR;
            if (!strncmp(p, "WARN ", 5))  return LL_WARN;
            if (!strncmp(p, "INFO ", 5))  return LL_INFO;
        }
    }

    /* Legacy undated format heuristic (pre-timestamp LOG_* lines):
     * LOG_FAIL/LOG_ERR/LOG_NULL all use stderr and prefix with [domain];
     * we treat those as ERROR level. Boot-time printfs use explicit
     * FATAL/WARN markers. Everything else INFO. */
    if (strstr(line, "FATAL") || strstr(line, "PANIC") ||
        strstr(line, "ABORT"))
        return LL_FATAL;
    if (strstr(line, "WARNING") || strstr(line, "WARN:") ||
        strstr(line, "[watchdog] ESCALATION"))
        return LL_WARN;
    if (line[0] == '[' && strstr(line, "(): ") &&
        (strstr(line, "GUARD FAILED") || strstr(line, "FAIL") ||
         strstr(line, "failed") || strstr(line, "error") ||
         strstr(line, "ERROR")))
        return LL_ERROR;
    return LL_INFO;
}

bool diag_rpc_getnodelog(const struct json_value *params, bool help,
                         struct json_value *result)
{
    RPC_HELP(help, result,
        "getnodelog <pattern> [since_secs=300] [max_lines=50] [level=all]\n"
        "\nReverse-scan node.log. `pattern` is POSIX-extended regex.\n"
        "`level` one of: all, info, warn, error, fatal.\n"
        "`since_secs` filters lines with parseable timestamps; undated "
        "legacy lines remain eligible and are counted in "
        "`undated_lines_included`. Pass 0 to disable timestamp filtering.\n"
        "\nResult: { lines: [...], scanned_bytes, truncated, log_path }");

    const char *pattern = json_get_str(json_at(params, 0));
    if (!pattern || !pattern[0]) {
        json_set_str(result, "getnodelog: missing pattern");
        LOG_FAIL("diag", "getnodelog: missing pattern");
    }
    size_t plen = strlen(pattern);
    if (plen > NODELOG_MAX_PATTERN_LEN) {
        json_set_str(result, "getnodelog: pattern too long");
        LOG_FAIL("diag", "getnodelog: pattern too long (%zu > %d)",
                 plen, NODELOG_MAX_PATTERN_LEN);
    }

    int64_t since_secs = json_at(params, 1) ?
        json_get_int(json_at(params, 1)) : NODELOG_DEFAULT_SINCE_SECS;
    if (since_secs < 0) since_secs = 0;
    if (since_secs > NODELOG_MAX_SINCE_SECS)
        since_secs = NODELOG_MAX_SINCE_SECS;

    int64_t max_lines = json_at(params, 2) ?
        json_get_int(json_at(params, 2)) : NODELOG_DEFAULT_MAX_LINES;
    if (max_lines < 1) max_lines = 1;
    if (max_lines > NODELOG_MAX_MAX_LINES)
        max_lines = NODELOG_MAX_MAX_LINES;

    const char *level_str = json_at(params, 3) ?
        json_get_str(json_at(params, 3)) : NULL;
    int want_level_i = parse_level(level_str);
    if (want_level_i < 0) {
        json_set_str(result, "getnodelog: bad level "
                     "(want all|info|warn|error|fatal)");
        LOG_FAIL("diag", "getnodelog: bad level '%s'",
                 level_str ? level_str : "");
    }
    enum log_level want_level = (enum log_level)want_level_i;

    const char *datadir = diag_datadir();
    if (!datadir[0]) {
        json_set_str(result, "getnodelog: datadir not configured");
        LOG_FAIL("diag", "getnodelog: datadir not configured");
    }

    char log_path[1280];
    snprintf(log_path, sizeof(log_path), "%s/node.log", datadir);

    int fd = open(log_path, O_RDONLY);
    if (fd < 0) {
        json_set_str(result, "getnodelog: cannot open node.log");
        LOG_FAIL("diag", "getnodelog: cannot open %s", log_path);
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        json_set_str(result, "getnodelog: fstat failed on node.log");
        LOG_FAIL("diag", "getnodelog: fstat failed on %s", log_path);
    }

    regex_t re;
    int rc = regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB);
    if (rc != 0) {
        char errbuf[128];
        regerror(rc, &re, errbuf, sizeof(errbuf));
        close(fd);
        json_set_str(result, "getnodelog: bad regex");
        LOG_FAIL("diag", "getnodelog: bad regex '%s': %s",
                 pattern, errbuf);
    }

    int64_t now = (int64_t)platform_time_wall_time_t();
    int64_t earliest = (since_secs > 0) ? (now - since_secs) : 0;

    /* Reverse-scan in NODELOG_CHUNK_SIZE chunks. Each chunk we read,
     * we split into lines and emit any complete lines that match.
     * Partial-line tail goes back into the next chunk. */
    json_set_object(result);
    struct json_value lines_arr = {0};
    json_set_array(&lines_arr);
    int emitted = 0;
    bool truncated = false;
    int64_t scanned = 0;
    off_t pos = st.st_size;
    int timestamped_candidates = 0;
    int timestamped_lines_skipped = 0;
    int undated_lines_included = 0;

    /* Each scanned line goes onto a stack so we emit in
     * newest-first order; lines_arr is built from that stack at the end. */
    char *stack[NODELOG_MAX_MAX_LINES];
    int stack_n = 0;
    char carry[NODELOG_CHUNK_SIZE + 1] = {0};
    size_t carry_len = 0;

    while (pos > 0 && emitted < max_lines &&
           scanned < NODELOG_MAX_SCAN_BYTES) {
        size_t want = (pos > NODELOG_CHUNK_SIZE) ? NODELOG_CHUNK_SIZE
                                                  : (size_t)pos;
        off_t start = pos - (off_t)want;
        char buf[NODELOG_CHUNK_SIZE + 1];
        ssize_t got = pread(fd, buf, want, start);
        if (got <= 0) break;
        buf[got] = '\0';
        scanned += got;
        pos = start;

        /* Combine `buf` (this chunk) with `carry` (partial line from
         * the previous-newer chunk). Process newline-separated lines
         * from the end. */
        size_t combined_cap = (size_t)got + carry_len + 1;
        char *combined = zcl_malloc(combined_cap, "diagnostics.node_log.combined");
        if (!combined) break;
        memcpy(combined, buf, got);
        memcpy(combined + got, carry, carry_len);
        combined[got + carry_len] = '\0';
        size_t combined_len = (size_t)got + carry_len;

        /* Walk backwards over `combined`, slicing at '\n'. */
        size_t line_end = combined_len;
        for (ssize_t i = (ssize_t)combined_len - 1;
             i >= -1 && emitted < max_lines; i--) {
            if (i < 0 || combined[i] == '\n') {
                size_t start_off = (i < 0) ? 0 : (size_t)i + 1;
                if (start_off < line_end) {
                    /* line = combined[start_off .. line_end) */
                    size_t llen = line_end - start_off;
                    if (i < 0 && pos > 0) {
                        /* Partial line at the start of this chunk —
                         * save as carry, don't emit yet (older chunk
                         * holds the head). */
                        if (llen > sizeof(carry) - 1) llen = sizeof(carry) - 1;
                        memcpy(carry, combined + start_off, llen);
                        carry_len = llen;
                        carry[llen] = '\0';
                    } else {
                        char *line = zcl_malloc(llen + 1, "diagnostics.node_log.line");
                        if (line) {
                            memcpy(line, combined + start_off, llen);
                            line[llen] = '\0';
                            /* Filter by regex + level. */
                            bool match = (regexec(&re, line, 0,
                                                  NULL, 0) == 0);
                            enum log_level lvl = line_level(line);
                            bool level_ok = (want_level == LL_ALL) ||
                                            (lvl >= want_level);
                            bool since_ok = true;
                            bool undated_candidate = false;
                            if (match && level_ok && since_secs > 0) {
                                int64_t line_ts = 0;
                                if (line_timestamp_unix(line, now, &line_ts)) {
                                    timestamped_candidates++;
                                    since_ok = (line_ts >= earliest &&
                                                line_ts <= now);
                                    if (!since_ok)
                                        timestamped_lines_skipped++;
                                } else {
                                    undated_candidate = true;
                                }
                            }
                            if (match && level_ok && since_ok &&
                                stack_n < NODELOG_MAX_MAX_LINES) {
                                stack[stack_n++] = line;
                                emitted++;
                                if (undated_candidate)
                                    undated_lines_included++;
                            } else {
                                free(line);
                            }
                        }
                        carry_len = 0;
                    }
                }
                line_end = (size_t)i;
            }
            if (i < 0) break;
        }
        free(combined);
        if (pos == 0) break;
    }

    if (pos > 0 && scanned >= NODELOG_MAX_SCAN_BYTES)
        truncated = true;

    /* The reverse scan pushes newest matches first, so preserve stack order. */
    for (int i = 0; i < stack_n; i++) {
        struct json_value lv = {0};
        json_set_str(&lv, stack[i]);
        json_push_back(&lines_arr, &lv);
        json_free(&lv);
        free(stack[i]);
    }

    json_push_kv(result, "lines", &lines_arr);
    json_free(&lines_arr);
    json_push_kv_int(result, "scanned_bytes", scanned);
    json_push_kv_bool(result, "truncated", truncated);
    json_push_kv_str(result, "log_path", log_path);
    json_push_kv_int(result, "emitted", emitted);
    json_push_kv_int(result, "since_secs", since_secs);
    json_push_kv_int(result, "earliest_unix", earliest);
    json_push_kv_str(result, "timestamp_filter",
                     since_secs > 0 ? "timestamped_lines" : "disabled");
    json_push_kv_int(result, "timestamped_candidates",
                     timestamped_candidates);
    json_push_kv_int(result, "timestamped_lines_skipped",
                     timestamped_lines_skipped);
    json_push_kv_int(result, "undated_lines_included",
                     undated_lines_included);
    json_push_kv_bool(result, "since_filter_complete",
                      since_secs == 0 || undated_lines_included == 0);

    regfree(&re);
    close(fd);
    return true;
}
