/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "config/boot_shutdown_marker.h"

#include "event/event.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZCL_SHUTDOWN_MARKER_NAME ".shutdown_clean"

/* ── Module-level cache ───────────────────────────────────────────────
 * detect_unclean() parses the marker's v2 binding into g_cached_binding
 * before it unlinks the on-disk file. node_db_open's probe consumes it
 * (single-use). g_schema_version is the value baked into the next marker. */
static struct shutdown_clean_binding g_cached_binding;   /* valid=false at start */
static int                           g_schema_version = -1;
static _Atomic bool                  g_quick_check_skipped;
static _Atomic bool                  g_quick_check_deferred;
static _Atomic bool                  g_quick_check_probe_consumed;

/* Tier-2 P2: the fast-restart binding parsed from THIS boot's marker (cached
 * before detect_unclean unlinks the file). Separate from g_cached_binding so
 * the quick_check probe's single-use consume of that cache does not wipe it —
 * the P2 evaluate point runs AFTER node_db_open. */
static struct shutdown_clean_binding g_cached_fr;        /* fr_valid=false start */
/* Facts to bake into the NEXT clean-shutdown marker (set at shutdown). */
static struct fast_restart_shutdown_facts g_fr_facts;    /* valid=false at start */

static void marker_hex32(char *out /* >=65 */, const uint8_t *b)
{
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = h[(b[i] >> 4) & 0xF];
        out[i * 2 + 1] = h[b[i] & 0xF];
    }
    out[64] = '\0';
}

/* Parse exactly 64 lowercase/uppercase hex chars into out[32]. */
static bool marker_unhex32(const char *s, uint8_t *out)
{
    for (int i = 0; i < 64; i++) {
        char c = s[i];
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return false;
        if (i & 1) out[i / 2] |= (uint8_t)v;
        else       out[i / 2]  = (uint8_t)(v << 4);
    }
    return true;
}

static bool boot_shutdown_marker_path(char *out, size_t out_n,
                                      const char *datadir,
                                      const char *name)
{
    if (!out || out_n == 0 || !datadir || !*datadir || !name || !*name)
        return false;

    int n = snprintf(out, out_n, "%s/%s", datadir, name);
    return n >= 0 && (size_t)n < out_n;
}

static bool marker_write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0)
            return false;
        off += (size_t)n;
    }
    return true;
}

/* ── Pure format/parse/decide helpers ─────────────────────────────── */

int boot_shutdown_marker_format(char *buf, size_t n, int64_t unix_seconds,
                                const struct shutdown_clean_binding *b)
{
    if (!buf || n == 0 || !b)
        return -1;
    if (!b->valid) {
        /* Legacy timestamp-only marker (node.db identity unavailable). */
        return snprintf(buf, n, "%lld\n", (long long)unix_seconds);
    }
    int off = snprintf(buf, n,
                    "%lld\n"
                    "magic=ZCLSHUT\n"
                    "version=2\n"
                    "node_db_size=%lld\n"
                    "node_db_change_counter=%u\n"
                    "node_db_version_valid_for=%u\n"
                    "schema_version=%d\n"
                    "wal_checkpointed=1\n",
                    (long long)unix_seconds,
                    (long long)b->node_db_size,
                    b->change_counter,
                    b->version_valid_for,
                    b->schema_version);
    if (off < 0 || (size_t)off >= n)
        return off;

    /* Tier-2 P2 fast-restart binding (optional; version stays 2 so a pre-P2
     * binary still parses the quick_check identity and simply ignores these
     * unknown keys). */
    if (b->fr_valid) {
        char tip_hex[65], coins_hex[65];
        marker_hex32(tip_hex, b->fr_tip_hash);
        marker_hex32(coins_hex, b->fr_coins_best_hash);
        int off2 = snprintf(buf + off, n - (size_t)off,
                    "fast_restart=1\n"
                    "fr_tip_height=%lld\n"
                    "fr_tip_hash=%s\n"
                    "fr_coins_best_height=%lld\n"
                    "fr_coins_best_hash=%s\n"
                    "fr_block_index_count=%lld\n"
                    "fr_mmb_leaves=%lld\n"
                    "fr_sapling_ckpt_height=%lld\n",
                    (long long)b->fr_tip_height, tip_hex,
                    (long long)b->fr_coins_best_height, coins_hex,
                    (long long)b->fr_block_index_count,
                    (long long)b->fr_mmb_leaves,
                    (long long)b->fr_sapling_ckpt_height);
        if (off2 < 0)
            return off2;
        off += off2;
    }
    return off;
}

/* Return the value string for `key=` if present on any line of [text,text+len),
 * copied into `val` (NUL-terminated). Returns true if found. */
static bool marker_find_kv(const char *text, size_t len,
                           const char *key, char *val, size_t val_n)
{
    size_t key_len = strlen(key);
    size_t i = 0;
    while (i < len) {
        size_t line_start = i;
        while (i < len && text[i] != '\n')
            i++;
        size_t line_len = i - line_start;
        if (i < len)
            i++; /* skip '\n' */
        if (line_len > key_len &&
            strncmp(text + line_start, key, key_len) == 0 &&
            text[line_start + key_len] == '=') {
            const char *v = text + line_start + key_len + 1;
            size_t v_len = line_len - key_len - 1;
            if (v_len >= val_n)
                v_len = val_n - 1;
            memcpy(val, v, v_len);
            val[v_len] = '\0';
            return true;
        }
    }
    return false;
}

bool boot_shutdown_marker_parse(const char *text, size_t len,
                                struct shutdown_clean_binding *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!text || len == 0)
        return false;

    char v[64];

    if (!marker_find_kv(text, len, "magic", v, sizeof(v)) ||
        strcmp(v, "ZCLSHUT") != 0)
        return false;
    if (!marker_find_kv(text, len, "version", v, sizeof(v)) ||
        strcmp(v, "2") != 0)
        return false;
    if (!marker_find_kv(text, len, "wal_checkpointed", v, sizeof(v)) ||
        strcmp(v, "1") != 0)
        return false;

    if (!marker_find_kv(text, len, "node_db_size", v, sizeof(v)))
        return false;
    errno = 0;
    char *end = NULL;
    long long sz = strtoll(v, &end, 10);
    if (errno != 0 || end == v || sz < 0)
        return false;
    out->node_db_size = (int64_t)sz;

    if (!marker_find_kv(text, len, "node_db_change_counter", v, sizeof(v)))
        return false;
    errno = 0;
    unsigned long cc = strtoul(v, &end, 10);
    if (errno != 0 || end == v)
        return false;
    out->change_counter = (uint32_t)cc;

    if (!marker_find_kv(text, len, "node_db_version_valid_for", v, sizeof(v)))
        return false;
    errno = 0;
    unsigned long vvf = strtoul(v, &end, 10);
    if (errno != 0 || end == v)
        return false;
    out->version_valid_for = (uint32_t)vvf;

    /* schema_version is advisory; default -1 if absent/garbage. */
    out->schema_version = -1;
    if (marker_find_kv(text, len, "schema_version", v, sizeof(v))) {
        errno = 0;
        long sv = strtol(v, &end, 10);
        if (errno == 0 && end != v)
            out->schema_version = (int)sv;
    }

    out->valid = true;

    /* Tier-2 P2 fast-restart binding (optional). Present iff `fast_restart=1`
     * and every fr_* field parses; otherwise fr_valid stays false and only the
     * v2 quick_check binding above is usable. */
    if (marker_find_kv(text, len, "fast_restart", v, sizeof(v)) &&
        strcmp(v, "1") == 0) {
        char hx[80];
        bool fr_ok = true;

        if (marker_find_kv(text, len, "fr_tip_height", v, sizeof(v))) {
            errno = 0; long long x = strtoll(v, &end, 10);
            if (errno || end == v) fr_ok = false; else out->fr_tip_height = x;
        } else fr_ok = false;

        if (fr_ok && marker_find_kv(text, len, "fr_tip_hash", hx, sizeof(hx)) &&
            strlen(hx) == 64 && marker_unhex32(hx, out->fr_tip_hash)) {
            /* ok */
        } else fr_ok = false;

        if (fr_ok && marker_find_kv(text, len, "fr_coins_best_height",
                                    v, sizeof(v))) {
            errno = 0; long long x = strtoll(v, &end, 10);
            if (errno || end == v) fr_ok = false;
            else out->fr_coins_best_height = x;
        } else fr_ok = false;

        if (fr_ok &&
            marker_find_kv(text, len, "fr_coins_best_hash", hx, sizeof(hx)) &&
            strlen(hx) == 64 && marker_unhex32(hx, out->fr_coins_best_hash)) {
            /* ok */
        } else fr_ok = false;

        if (fr_ok && marker_find_kv(text, len, "fr_block_index_count",
                                    v, sizeof(v))) {
            errno = 0; long long x = strtoll(v, &end, 10);
            if (errno || end == v || x < 0) fr_ok = false;
            else out->fr_block_index_count = x;
        } else fr_ok = false;

        if (fr_ok && marker_find_kv(text, len, "fr_mmb_leaves", v, sizeof(v))) {
            errno = 0; long long x = strtoll(v, &end, 10);
            if (errno || end == v) fr_ok = false; else out->fr_mmb_leaves = x;
        } else fr_ok = false;

        if (fr_ok && marker_find_kv(text, len, "fr_sapling_ckpt_height",
                                    v, sizeof(v))) {
            errno = 0; long long x = strtoll(v, &end, 10);
            if (errno || end == v) fr_ok = false;
            else out->fr_sapling_ckpt_height = x;
        } else fr_ok = false;

        out->fr_valid = fr_ok;
    }
    return true;
}

bool boot_shutdown_marker_can_skip(const struct shutdown_clean_binding *b,
                                   const struct node_db_file_identity *cur)
{
    if (!b || !cur || !b->valid || !cur->present)
        return false;
    if (cur->wal_present)
        return false;
    if (cur->size != b->node_db_size)
        return false;
    if (cur->change_counter != b->change_counter)
        return false;
    if (cur->version_valid_for != b->version_valid_for)
        return false;
    return true;
}

/* ── File identity read (pristine, pre-open) ──────────────────────── */

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

bool node_db_file_identity_read(const char *node_db_path,
                                struct node_db_file_identity *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!node_db_path || !*node_db_path)
        return false;

    int fd = open(node_db_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;

    struct stat st;
    uint8_t hdr[100];
    bool ok = false;
    if (fstat(fd, &st) == 0 && st.st_size >= (off_t)sizeof(hdr)) {
        ssize_t r = pread(fd, hdr, sizeof(hdr), 0);
        if (r == (ssize_t)sizeof(hdr) &&
            memcmp(hdr, "SQLite format 3\0", 16) == 0) {
            out->present = true;
            out->size = (int64_t)st.st_size;
            out->change_counter = be32(hdr + 24);
            out->version_valid_for = be32(hdr + 92);
            ok = true;
        }
    }
    close(fd);

    if (ok) {
        /* WAL present iff <node.db>-wal exists with size > 0. */
        char wal[1200];
        int n = snprintf(wal, sizeof(wal), "%s-wal", node_db_path);
        if (n > 0 && (size_t)n < sizeof(wal)) {
            struct stat wst;
            out->wal_present = (stat(wal, &wst) == 0 && wst.st_size > 0);
        }
    }
    return ok;
}

/* ── Boot lifecycle ───────────────────────────────────────────────── */

void boot_shutdown_marker_set_schema_version(int schema_version)
{
    g_schema_version = schema_version;
}

bool boot_shutdown_marker_quick_check_was_skipped(void)
{
    return atomic_load(&g_quick_check_skipped);
}

bool boot_shutdown_marker_quick_check_was_deferred(void)
{
    return atomic_load(&g_quick_check_deferred);
}

void boot_shutdown_marker_reset_for_test(void)
{
    memset(&g_cached_binding, 0, sizeof(g_cached_binding));
    memset(&g_cached_fr, 0, sizeof(g_cached_fr));
    memset(&g_fr_facts, 0, sizeof(g_fr_facts));
    g_schema_version = -1;
    atomic_store(&g_quick_check_skipped, false);
    atomic_store(&g_quick_check_deferred, false);
    atomic_store(&g_quick_check_probe_consumed, false);
}

void boot_shutdown_marker_set_fast_restart_facts(
    const struct fast_restart_shutdown_facts *facts)
{
    if (facts)
        g_fr_facts = *facts;
    else
        memset(&g_fr_facts, 0, sizeof(g_fr_facts));
}

bool boot_shutdown_marker_peek_fast_restart_binding(
    struct shutdown_clean_binding *out)
{
    if (!out)
        return false;
    *out = g_cached_fr;
    return g_cached_fr.fr_valid;
}

bool boot_shutdown_marker_quick_check_probe(const char *node_db_path)
{
    /* Single-use for this process: a second call cannot reuse a stale
     * binding or re-arm deferral. */
    if (atomic_exchange(&g_quick_check_probe_consumed, true))
        return false;

    struct shutdown_clean_binding b = g_cached_binding;
    memset(&g_cached_binding, 0, sizeof(g_cached_binding));

    struct node_db_file_identity cur;
    bool have = node_db_file_identity_read(node_db_path, &cur);

    if (b.valid && have && boot_shutdown_marker_can_skip(&b, &cur)) {
        atomic_store(&g_quick_check_skipped, true);
        printf("[boot] quick_check skipped (verified-clean shutdown)\n");
        return true;
    }

    /* Existing SQLite node.db without a matching clean binding. SQLite already
     * recovered any WAL on open. PRAGMA quick_check(1) on a multi-GB
     * production file can take hours of uninterruptible I/O and holds
     * listen/READY hostage. Defer to the background recheck, which fail-closes
     * via EV_OPERATOR_NEEDED. Fresh/absent files return false so the cheap
     * blocking check and quarantine-rebuild path remain. */
    if (have && cur.present) {
        atomic_store(&g_quick_check_deferred, true);
        printf("[boot] quick_check deferred to background "
               "(no verified-clean binding; fail-closed recheck armed)\n");
        return true;
    }
    return false;
}

bool boot_shutdown_marker_detect_unclean(const char *datadir)
{
    char marker_path[1024];
    char wal_path[1024];
    if (!boot_shutdown_marker_path(marker_path, sizeof(marker_path),
                                   datadir, ZCL_SHUTDOWN_MARKER_NAME) ||
        !boot_shutdown_marker_path(wal_path, sizeof(wal_path),
                                   datadir, "node.db-wal")) {
        fprintf(stderr,
                "[boot] Cannot inspect clean shutdown marker: invalid datadir\n");
        return false;
    }

    struct stat wal_st;
    bool wal_exists = (stat(wal_path, &wal_st) == 0 && wal_st.st_size > 0);
    bool marker_exists = (access(marker_path, F_OK) == 0);
    bool unclean = !marker_exists && wal_exists;

    /* Cache the v2 content-binding (if any) BEFORE unlinking, so
     * node_db_open's quick_check-skip probe can consult it. A parse failure
     * or a WAL present → no cached binding → the probe defers an existing
     * node.db to the background recheck instead of blocking listen.
     * The same parse also yields the Tier-2 fast-restart binding (g_cached_fr),
     * kept separate so the quick_check probe's consume does not wipe it. */
    memset(&g_cached_binding, 0, sizeof(g_cached_binding));
    memset(&g_cached_fr, 0, sizeof(g_cached_fr));
    atomic_store(&g_quick_check_skipped, false);
    atomic_store(&g_quick_check_deferred, false);
    atomic_store(&g_quick_check_probe_consumed, false);
    if (marker_exists && !wal_exists) {
        FILE *mf = fopen(marker_path, "r");
        if (mf) {
            char buf[1024];
            size_t rd = fread(buf, 1, sizeof(buf) - 1, mf);
            fclose(mf);
            struct shutdown_clean_binding parsed;
            if (boot_shutdown_marker_parse(buf, rd, &parsed)) {
                g_cached_binding = parsed;
                if (parsed.fr_valid)
                    g_cached_fr = parsed;
            }
        }
    }

    if (unclean) {
        printf("[boot] Unclean shutdown detected (WAL=%lldB, "
               "clean marker missing)\n",
               (long long)wal_st.st_size);
        event_emitf(EV_CRASH_RECOVERY_START, 0,
                    "wal_size=%lld clean_marker=missing",
                    (long long)wal_st.st_size);
    } else if (!marker_exists) {
        printf("[boot] First boot or marker absent (no WAL)\n");
    } else {
        printf("[boot] Clean shutdown marker present\n");
    }

    unlink(marker_path);
    return unclean;
}

bool boot_shutdown_marker_write_clean(const char *datadir)
{
    char path[1024];
    char tmp[1088];
    char node_db_path[1088];
    if (!boot_shutdown_marker_path(path, sizeof(path),
                                   datadir, ZCL_SHUTDOWN_MARKER_NAME))
        return false;

    int tn = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int dn = snprintf(node_db_path, sizeof(node_db_path), "%s/node.db", datadir);
    if (tn < 0 || (size_t)tn >= sizeof(tmp) ||
        dn < 0 || (size_t)dn >= sizeof(node_db_path))
        return false;

    /* Bind the marker to node.db's final on-disk identity. The DB has already
     * been WAL-checkpointed and closed by the shutdown path, so the header we
     * read here is exactly what the next boot will see before it opens the
     * file. If node.db is missing/unreadable we still write a legacy
     * timestamp-only marker (no skip binding) — identical to prior behavior. */
    struct node_db_file_identity id;
    struct shutdown_clean_binding b;
    memset(&b, 0, sizeof(b));
    if (node_db_file_identity_read(node_db_path, &id) && !id.wal_present) {
        b.valid = true;
        b.node_db_size = id.size;
        b.change_counter = id.change_counter;
        b.version_valid_for = id.version_valid_for;
        b.schema_version = g_schema_version;
    }

    /* Fold in the Tier-2 fast-restart facts, if the shutdown path recorded a
     * complete set. Requires the v2 identity too (b.valid): a fast restart
     * always verifies node.db cleanliness first. */
    if (b.valid && g_fr_facts.valid) {
        b.fr_valid = true;
        b.fr_tip_height = g_fr_facts.tip_height;
        memcpy(b.fr_tip_hash, g_fr_facts.tip_hash, 32);
        b.fr_coins_best_height = g_fr_facts.coins_best_height;
        memcpy(b.fr_coins_best_hash, g_fr_facts.coins_best_hash, 32);
        b.fr_block_index_count = g_fr_facts.block_index_count;
        b.fr_mmb_leaves = g_fr_facts.mmb_leaves;
        b.fr_sapling_ckpt_height = g_fr_facts.sapling_ckpt_height;
    }

    char content[1024];
    int clen = boot_shutdown_marker_format(content, sizeof(content),
                                           (int64_t)platform_time_wall_time_t(),
                                           &b);
    if (clen < 0 || (size_t)clen >= sizeof(content))
        return false;

    /* Crash-safe write: temp file + fsync + atomic rename. */
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        return false;
    bool ok = false;
    if (marker_write_all(fd, content, (size_t)clen) && fsync(fd) == 0)
        ok = true;
    if (close(fd) != 0)
        ok = false;
    if (!ok) {
        unlink(tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return false;
    }

    /* The marker is a durability claim, so its directory fsync is mandatory. */
    int dfd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0)
        return false;
    ok = fsync(dfd) == 0;
    if (close(dfd) != 0)
        ok = false;
    return ok;
}

bool boot_shutdown_marker_remove_clean(const char *datadir)
{
    char path[1024];
    if (!boot_shutdown_marker_path(path, sizeof(path), datadir,
                                   ZCL_SHUTDOWN_MARKER_NAME))
        return false;

    if (unlink(path) != 0 && errno != ENOENT)
        return false;

    int dfd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0)
        return false;
    bool ok = fsync(dfd) == 0;
    if (close(dfd) != 0)
        ok = false;
    return ok;
}
