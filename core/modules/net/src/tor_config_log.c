/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded Tor bootstrap configuration and current-boot log evidence
 * parsing, independent of the embedded Tor thread lifecycle. */

#include "net/tor_integration.h"
#include "util/log_macros.h"
#include "util/log_rotate.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The [rend] info stream lives in its OWN file. Tor publishes the one line
 * that proves this node's onion descriptor reached an HSDir —
 * "Uploaded hidden service descriptor (status 200 ..." from
 * dirclient.c — at log_info(LD_REND), so the readiness check in
 * tor_integration.c genuinely needs info level for that one domain. Sending
 * it to tor.log along with everything else is what made a field box carry a
 * 1,319 MB tor.log full of "[info]" lines under a torrc whose first line
 * says "Log notice file": the SECOND Log line silently raised the level of
 * the same destination. Splitting the destinations keeps tor.log at notice
 * — an operator's log, small enough to read — and confines the chatty
 * bootstrap evidence to a file whose only reader is this node's own
 * readiness poll. Both are size-bounded by tor_logs_rotate() below. */
bool tor_write_torrc(const char *datadir, uint16_t p2p_port,
                    bool reduced_padding)
{
    char torrc_path[1024];
    int pn = snprintf(torrc_path, sizeof(torrc_path), "%s/torrc", datadir);
    if (pn < 0 || (size_t)pn >= sizeof(torrc_path))
        LOG_FAIL("tor", "torrc path too long for datadir: %s", datadir);

    /* Localhost-only SocksPort — NOTHING connects to this. It exists only
     * because Tor will not bootstrap without a listener. Derivation keeps
     * isolated instances disjoint (8033→19999, 8035→20001). */
    uint16_t bootstrap_port = (uint16_t)(p2p_port + 11966);
    char body[8192];
    int bn = snprintf(body, sizeof(body),
        "SocksPort 127.0.0.1:%u\n"
        "DataDirectory %s/tor_data\n"
        "Log notice file %s/" TOR_LOG_BASENAME "\n"
        "Log info [rend] file %s/" TOR_REND_LOG_BASENAME "\n"
        /* The node owns SIGTERM/SIGINT (platform signal_handler). Left on,
         * Tor's libevent handlers swallow the node's shutdown signal, exit 0
         * on their own and the node never shuts down. Tor is ended by
         * tor_integration_stop(), not by a signal. */
        "__DisableSignalHandlers 1\n"
        "%s",
        bootstrap_port, datadir, datadir, datadir,
        reduced_padding ? "ReducedConnectionPadding 1\n" : "");
    if (bn < 0 || (size_t)bn >= sizeof(body))
        LOG_FAIL("tor", "torrc for %s does not fit its %zu-byte buffer",
                 datadir, sizeof(body));

    FILE *f = fopen(torrc_path, "w");
    if (!f)
        LOG_FAIL("tor", "failed to open torrc for writing: %s", torrc_path);

    /* A short or failed write would leave a torrc without
     * __DisableSignalHandlers (or any later line) that Tor still parses:
     * check the write, the flush and the close, and never leave the partial
     * file behind. */
    bool wrote = fwrite(body, 1, (size_t)bn, f) == (size_t)bn;
    bool flushed = wrote && fflush(f) == 0 && !ferror(f);
    bool closed = fclose(f) == 0;
    if (!wrote || !flushed || !closed) {
        /* tor_integration_start() returns false on our false, so Tor is never
         * started on this file; still, say so if the partial file survives. */
        if (unlink(torrc_path) != 0 && errno != ENOENT)
            ZCL_LOG_ERROR_ORIGIN("tor", "could not remove partial torrc %s: %s",
                                 torrc_path, strerror(errno));
        LOG_FAIL("tor", "failed to write torrc %s (wrote=%d flushed=%d closed=%d)",
                 torrc_path, wrote, flushed, closed);
    }
    return true;
}

bool tor_log_path(const char *datadir, char *out, size_t out_size)
{
    if (!datadir || !datadir[0] || !out || out_size == 0)
        return false;
    int n = snprintf(out, out_size, "%s/" TOR_LOG_BASENAME, datadir);
    return n > 0 && (size_t)n < out_size;
}

bool tor_rend_log_path(const char *datadir, char *out, size_t out_size)
{
    if (!datadir || !datadir[0] || !out || out_size == 0)
        return false;
    int n = snprintf(out, out_size, "%s/" TOR_REND_LOG_BASENAME, datadir);
    return n > 0 && (size_t)n < out_size;
}

/* Bound both Tor logs. Tor holds each file open O_APPEND for the life of the
 * process and an embedded Tor has no SIGHUP path that would make it reopen
 * one, so log_rotate_if_over copies and truncates in place rather than
 * renaming — see util/log_rotate.h. Returns the number of files rotated. */
int tor_logs_rotate(const char *datadir, int64_t max_bytes)
{
    char path[1024];
    int rotated = 0;
    if (tor_log_path(datadir, path, sizeof(path)) &&
        log_rotate_if_over(path, max_bytes, NULL))
        rotated++;
    if (tor_rend_log_path(datadir, path, sizeof(path)) &&
        log_rotate_if_over(path, max_bytes, NULL))
        rotated++;
    return rotated;
}

static void tor_log_seek_scan_start(FILE *f, long scan_from)
{
    if (scan_from > 0) {
        if (fseek(f, 0, SEEK_END) != 0 || ftell(f) < scan_from ||
            fseek(f, scan_from, SEEK_SET) != 0)
            rewind(f);
    }
}

static bool tor_log_copy_ephemeral_token(char *p, char *out, size_t out_size)
{
    char *end = p;
    while (*end && *end != '\n' && *end != '\r' && *end != ' ')
        end++;
    size_t len = (size_t)(end - p);
    if (len > 0 && len < out_size) {
        memcpy(out, p, len);
        out[len] = '\0';
        return true;
    }
    return false;
}

bool tor_log_last_ephemeral_address(const char *log_path, long scan_from,
                                    char *out, size_t out_size)
{
    if (!log_path || !out || out_size == 0)
        return false;

    FILE *f = fopen(log_path, "r");
    if (!f)
        return false;
    tor_log_seek_scan_start(f, scan_from);

    static const char marker[] = "ephemeral service created with address: ";
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        char *p = strstr(line, marker);
        if (!p)
            continue;
        p += sizeof(marker) - 1;
        if (tor_log_copy_ephemeral_token(p, out, out_size))
            found = true; /* the latest current-boot line supersedes */
    }
    fclose(f);
    return found;
}

bool tor_log_has_descriptor_publication(const char *log_path, long scan_from)
{
    if (!log_path)
        return false;

    FILE *f = fopen(log_path, "r");
    if (!f)
        return false;
    if (scan_from > 0) {
        if (fseek(f, 0, SEEK_END) != 0 || ftell(f) < scan_from ||
            fseek(f, scan_from, SEEK_SET) != 0)
            rewind(f);
    }

    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        /* Success-only: hostname presence and failed uploads do not count. */
        if (strstr(line, "DESCRIPTOR PUBLICATION") != NULL ||
            strstr(line, "Uploaded hidden service descriptor (status 200") != NULL ||
            strstr(line, "finished with status 200") != NULL ||
            strstr(line, "HS_DESC UPLOADED") != NULL) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}
