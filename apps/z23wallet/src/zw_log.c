/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: lifecycle-only logger. A line containing a registered secret is
 * replaced by a marker so cookies and passwords can never reach stderr or a
 * log file. Addresses and amounts are not logged by callers. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "base/cleanse.h"
#include "zw.h"

#define MAX_SECRETS 4

static FILE *g_file;
static char g_secrets[MAX_SECRETS][128];
static size_t g_next_secret;

void zw_log_open(const char *path)
{
    if (!path || !path[0]) return;
    g_file = fopen(path, "ab");
}

void zw_log_close(void)
{
    if (g_file) fclose(g_file);
    g_file = NULL;
    for (size_t i = 0; i < MAX_SECRETS; i++) memory_cleanse(g_secrets[i], sizeof(g_secrets[i]));
}

void zw_log_secret(const char *secret)
{
    if (!secret || !secret[0] || strlen(secret) >= sizeof(g_secrets[0])) return;
    memcpy(g_secrets[g_next_secret], secret, strlen(secret) + 1);
    g_next_secret = (g_next_secret + 1) % MAX_SECRETS;
}

void zw_log(const char *fmt, ...)
{
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    for (size_t i = 0; i < MAX_SECRETS; i++)
        if (g_secrets[i][0] && strstr(line, g_secrets[i])) {
            snprintf(line, sizeof(line), "[line withheld: contained a secret]");
            break;
        }
    fprintf(stderr, "z23-wallet: %s\n", line);
    if (g_file) {
        fprintf(g_file, "%s\n", line);
        fflush(g_file);
    }
}
