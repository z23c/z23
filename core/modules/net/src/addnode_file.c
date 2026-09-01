/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * See net/addnode_file.h. */

#include "net/addnode_file.h"
#include "util/log_macros.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool addnode_file_line_is_blank(const char *line)
{
    if (!line)
        return true;
    const char *p = line;
    while (*p == ' ' || *p == '\t')
        p++;
    return *p == '\0' || *p == '\n' || *p == '\r' || *p == '#';
}

bool addnode_file_parse_line(const char *line, char *host_out,
                              size_t host_cap, uint16_t *port_out)
{
    if (!line || !host_out || host_cap == 0 || !port_out)
        return false;
    *port_out = 0;

    if (addnode_file_line_is_blank(line))
        return false;

    const char *p = line;
    while (*p == ' ' || *p == '\t')
        p++;

    char token[320];
    size_t n = 0;
    while (p[n] && p[n] != '\n' && p[n] != '\r' && p[n] != '#' &&
           p[n] != ' ' && p[n] != '\t') {
        if (n >= sizeof(token) - 1)
            return false; /* oversized token — reject rather than truncate */
        token[n] = p[n];
        n++;
    }
    token[n] = '\0';
    if (n == 0)
        return false;

    /* Only a single trailing ":PORT" is treated as a port suffix — a token
     * with more than one colon (bare IPv6, unbracketed) is passed through
     * whole as the host and left on the default port rather than guessing
     * which colon is the port separator. */
    char *colon = strrchr(token, ':');
    if (colon && colon != token && strchr(token, ':') == colon) {
        char *end = NULL;
        long v = strtol(colon + 1, &end, 10);
        if (end && *end == '\0' && v > 0 && v < 65536) {
            *port_out = (uint16_t)v;
            *colon = '\0';
        }
    }

    if (token[0] == '\0' || strlen(token) >= host_cap)
        return false;

    snprintf(host_out, host_cap, "%s", token);
    return true;
}

int addnode_file_load(const char *path, addnode_file_add_fn add_cb, void *ctx)
{
    if (!path || !add_cb)
        return -1;

    FILE *f = fopen(path, "re");
    if (!f) {
        if (errno == ENOENT)
            return 0; /* operator didn't drop a peers list — clean no-op */
        LOG_WARN("net", "addnode-file: open failed for %s: %s",
                 path, strerror(errno));
        return -1;
    }

    char line[320];
    int lineno = 0, loaded = 0, skipped = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char host[256];
        uint16_t port = 0;
        if (addnode_file_parse_line(line, host, sizeof(host), &port)) {
            add_cb(host, port, ctx);
            loaded++;
        } else if (!addnode_file_line_is_blank(line)) {
            LOG_WARN("net", "addnode-file: skipping malformed line %d in %s",
                     lineno, path);
            skipped++;
        }
    }
    fclose(f);

    printf("addnode-file: loaded %d peer(s) from %s (%d line(s) skipped)\n",
           loaded, path, skipped);
    return loaded;
}
