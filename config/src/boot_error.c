/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Renders pre-registry boot failures in the typed command-error shape
 * (code / phase / message / evidence / next[]). Contract + caller rules:
 * config/include/config/boot_error.h. libc only, by design. */

#include "config/boot_error.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static bool g_fatal_reported;
static char g_first_code[BOOT_ERROR_CODE_MAX];
static char g_last_render[BOOT_ERROR_RENDER_MAX];

/* Append to a bounded cursor. Silently stops at the cap — a truncated
 * diagnostic is still better than none, and the fixed cap keeps this callable
 * before any allocator policy is set up. */
static void render_append(char *buf, size_t cap, size_t *off,
                          const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static void render_append(char *buf, size_t cap, size_t *off,
                          const char *fmt, ...)
{
    if (*off >= cap)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *off, cap - *off, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    *off = (size_t)n >= cap - *off ? cap : *off + (size_t)n;
}

void boot_error_report(enum boot_error_level level, const char *code,
                       const char *phase, const char *message,
                       const struct boot_error_next *next, size_t next_count,
                       const char *evidence_fmt, ...)
{
    const char *tag = level == BOOT_ERROR_WARN ? "WARN" : "FATAL";
    const char *safe_code = code && code[0] ? code : "BOOT_UNSPECIFIED";
    const char *safe_phase = phase && phase[0] ? phase : "boot";
    const char *safe_msg = message && message[0] ? message
                                                 : "(no message supplied)";

    char evidence[512];
    evidence[0] = '\0';
    if (evidence_fmt && evidence_fmt[0]) {
        va_list ap;
        va_start(ap, evidence_fmt);
        (void)vsnprintf(evidence, sizeof(evidence), evidence_fmt, ap);
        va_end(ap);
    }

    size_t off = 0;
    g_last_render[0] = '\0';
    render_append(g_last_render, sizeof(g_last_render), &off,
                  "\n%s boot: %s\n", tag, safe_msg);
    render_append(g_last_render, sizeof(g_last_render), &off,
                  "  code:     %s\n", safe_code);
    render_append(g_last_render, sizeof(g_last_render), &off,
                  "  phase:    %s\n", safe_phase);
    if (evidence[0])
        render_append(g_last_render, sizeof(g_last_render), &off,
                      "  evidence: %s\n", evidence);
    if (next) {
        size_t shown = 0;
        for (size_t i = 0; i < next_count && shown < BOOT_ERROR_MAX_NEXT; i++) {
            if (!next[i].command || !next[i].command[0])
                continue;
            shown++;
            render_append(g_last_render, sizeof(g_last_render), &off,
                          "  next[%zu]:  %s\n", shown, next[i].command);
            if (next[i].reason && next[i].reason[0])
                render_append(g_last_render, sizeof(g_last_render), &off,
                              "            why: %s\n", next[i].reason);
        }
    }
    render_append(g_last_render, sizeof(g_last_render), &off, "\n");

    fputs(g_last_render, stderr);
    fflush(stderr);

    if (level == BOOT_ERROR_FATAL && !g_fatal_reported) {
        g_fatal_reported = true;
        (void)snprintf(g_first_code, sizeof(g_first_code), "%s", safe_code);
    }
}

bool boot_error_reported(void) { return g_fatal_reported; }

const char *boot_error_first_code(void) { return g_first_code; }

size_t boot_error_last_render(char *out, size_t cap)
{
    if (!out || cap == 0)
        return 0;
    size_t len = strlen(g_last_render);
    if (len >= cap)
        len = cap - 1;
    memcpy(out, g_last_render, len);
    out[len] = '\0';
    return len;
}

#ifdef ZCL_TESTING
void boot_error_reset_for_testing(void)
{
    g_fatal_reported = false;
    g_first_code[0] = '\0';
    g_last_render[0] = '\0';
}
#endif
