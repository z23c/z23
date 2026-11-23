/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: lifecycle-only logger. A line containing a registered secret is
 * replaced by a marker so cookies and passwords can never reach stderr or a
 * log file. Addresses and amounts are not logged by callers. */
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "base/cleanse.h"
#include "zw.h"

/* Each credential load registers three strings (the user:pass, the password
 * alone, the base64 header value); 16 slots keep the last several loads, and a
 * re-registered secret does not evict an older one. */
#define MAX_SECRETS 16

/* The worker thread registers secrets while the UI thread logs: one lock covers
 * the secret table and the file. */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static FILE *g_file;
/* A slot holds the longest secret there is: a whole Authorization value. */
static char g_secrets[MAX_SECRETS][sizeof(((struct zw_endpoint *)0)->auth)];
static size_t g_next_secret;

void zw_log_open(const char *path)
{
    if (!path || !path[0]) return;
    FILE *f = zw_fopen_append_private(path);
    pthread_mutex_lock(&g_mu);
    g_file = f;
    pthread_mutex_unlock(&g_mu);
}

void zw_log_close(void)
{
    pthread_mutex_lock(&g_mu);
    if (g_file) fclose(g_file);
    g_file = NULL;
    for (size_t i = 0; i < MAX_SECRETS; i++) memory_cleanse(g_secrets[i], sizeof(g_secrets[i]));
    pthread_mutex_unlock(&g_mu);
}

void zw_log_secret(const char *secret)
{
    if (!secret || !secret[0] || strlen(secret) >= sizeof(g_secrets[0])) return;
    pthread_mutex_lock(&g_mu);
    bool known = false;
    for (size_t i = 0; i < MAX_SECRETS && !known; i++) known = !strcmp(g_secrets[i], secret);
    if (!known) {
        memcpy(g_secrets[g_next_secret], secret, strlen(secret) + 1);
        g_next_secret = (g_next_secret + 1) % MAX_SECRETS;
    }
    pthread_mutex_unlock(&g_mu);
}

void zw_log(const char *fmt, ...)
{
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    pthread_mutex_lock(&g_mu);
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
    pthread_mutex_unlock(&g_mu);
}
