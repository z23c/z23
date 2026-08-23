/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Peer lifecycle observability: a session that opens in node.log must close
 * in node.log.
 *
 * The live failure this pins: the connect side wrote a structured
 * "peer_connected" JSON line, while the close side only called event_emitf()
 * into the event ring, which never reaches node.log. A hub node's log held 293
 * peer_connected lines and ZERO disconnect lines of any kind — connections
 * vanished with no line, no reason and no counter, and a whole class of
 * peering failure was undiagnosable from the log a reader actually has.
 *
 * Two prongs:
 *   (A) behavioural — p2p_log_peer_close() renders one well-formed line per
 *       call, with the named reason, the named source, the state the session
 *       reached, direction and lifetime, for EVERY reason enumerator;
 *   (B) structural — the single place a p2p_node leaves nodes[] emits the
 *       terminal line, and the teardown path does too, so no removal path is
 *       silent. Prong B is a source scan because there is no way to fake a
 *       whole connman socket loop in-process, and a comment cannot keep a
 *       future edit honest. */

#include "test/test_core.h"
#include "net/net.h"
#include "core/utiltime.h"
#include "platform/os_proc.h"
#include "util/log_json.h"

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool contains(const char *hay, const char *needle)
{
    return hay && needle && strstr(hay, needle) != NULL;
}

/* ── capture: log_jsonf() reaches the log through LogPrintStr(), which writes
 * to stderr. Redirect fd 2 into a temp file for the duration of one emit so
 * the test reads the REAL emitter output, not a re-implementation of it. ── */
static bool capture_close_line(const struct p2p_node *node, const char *event,
                               enum p2p_disconnect_reason reason,
                               enum p2p_disconnect_source source,
                               char *out, size_t cap)
{
    if (!out || cap == 0) return false;
    out[0] = '\0';

    char path[] = "/tmp/zcl_peer_close_XXXXXX";
    int tmp_fd = mkstemp(path);
    if (tmp_fd < 0) return false;

    int saved = dup(STDERR_FILENO);
    if (saved < 0) { close(tmp_fd); unlink(path); return false; }

    fflush(stderr);
    if (dup2(tmp_fd, STDERR_FILENO) < 0) {
        close(saved); close(tmp_fd); unlink(path);
        return false;
    }

    p2p_log_peer_close(node, event, reason, source);

    fflush(stderr);
    (void)dup2(saved, STDERR_FILENO);
    close(saved);
    (void)lseek(tmp_fd, 0, SEEK_SET);

    ssize_t n = read(tmp_fd, out, cap - 1);
    close(tmp_fd);
    unlink(path);
    if (n < 0) { out[0] = '\0'; return false; }
    out[n] = '\0';
    return true;
}

/* A zeroed node is enough: the emitter reads only scalar identity fields, so
 * no mutex, bloom filter or net_manager has to exist. Heap, not stack — the
 * node struct carries per-peer buffers and is far too big for a test frame. */
static struct p2p_node *make_node(const char *addr_name, int id, bool inbound,
                                  enum peer_state state, int version,
                                  int64_t age_secs)
{
    struct p2p_node *n = calloc(1, sizeof(*n));
    if (!n) return NULL;
    snprintf(n->addr_name, sizeof(n->addr_name), "%s", addr_name);
    n->id = (node_id_t)id;
    n->inbound = inbound;
    n->state = state;
    n->version = version;
    n->misbehavior = 0;
    n->endpoint_generation = (uint64_t)id + 1u;
    /* GetTime() is the emitter's own clock, so the reported lifetime is
     * age_secs — or age_secs+1 if the wall second ticks between here and the
     * emit, which lifetime_is() below tolerates. */
    n->time_connected = GetTime() - age_secs;
    return n;
}

/* lifetime_secs is a wall-clock difference, so accept the one-second tick. */
static bool lifetime_is(const char *line, long long secs)
{
    char want[64];
    snprintf(want, sizeof(want), "\"lifetime_secs\":%lld,", secs);
    if (contains(line, want)) return true;
    snprintf(want, sizeof(want), "\"lifetime_secs\":%lld,", secs + 1);
    return contains(line, want);
}

/* ── Prong A: every reason produces a named, paired line ───────────── */

static int test_close_line_shape(void)
{
    int failures = 0;
    TEST("peer_disconnect_log: close line carries addr/peer_id/state/reason") {
        struct p2p_node *n = make_node("203.0.113.9:8033", 7, false,
                                        PEER_SYNCING_HEADERS, 170020, 42);
        ASSERT(n != NULL);
        char buf[2048];
        ASSERT(capture_close_line(n, "peer_disconnected",
                                  P2P_DISCONNECT_HANDSHAKE_TIMEOUT,
                                  P2P_DISCONNECT_SOURCE_DIAL_SCHEDULER,
                                  buf, sizeof(buf)));
        ASSERT(contains(buf, "\"event\":\"peer_disconnected\","));
        ASSERT(contains(buf, "\"addr\":\"203.0.113.9:8033\""));
        ASSERT(contains(buf, "\"peer_id\":7"));
        ASSERT(contains(buf, "\"inbound\":false"));
        ASSERT(contains(buf, "\"state\":\"syncing_headers\""));
        ASSERT(contains(buf, "\"reason\":\"handshake_timeout\""));
        ASSERT(contains(buf, "\"source\":\"dial_scheduler\""));
        ASSERT(contains(buf, "\"version\":170020"));
        ASSERT(lifetime_is(buf, 42));
        ASSERT(contains(buf, "\"endpoint_generation\":8"));
        /* Exactly one line. */
        const char *nl = strchr(buf, '\n');
        ASSERT(nl != NULL);
        ASSERT(nl[1] == '\0');
        free(n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_inbound_direction_recorded(void)
{
    int failures = 0;
    TEST("peer_disconnect_log: inbound sessions close as inbound") {
        struct p2p_node *n = make_node("198.51.100.4:41234", 12, true,
                                        PEER_CONNECTED, 0, 3);
        ASSERT(n != NULL);
        char buf[2048];
        ASSERT(capture_close_line(n, "peer_disconnected",
                                  P2P_DISCONNECT_EVICTED,
                                  P2P_DISCONNECT_SOURCE_PEER_POLICY,
                                  buf, sizeof(buf)));
        ASSERT(contains(buf, "\"inbound\":true"));
        ASSERT(contains(buf, "\"reason\":\"evicted\""));
        ASSERT(contains(buf, "\"source\":\"peer_policy\""));
        free(n);
        PASS();
    } _test_next:;
    return failures;
}

/* Every reason a real path can pass must render as its own name. A new
 * enumerator without a name string would silently degrade every future
 * disconnect line to "unknown" — exactly the generic-reason blindness this
 * lane exists to remove. */
static int test_every_reason_is_named(void)
{
    int failures = 0;
    TEST("peer_disconnect_log: every reason/source enumerator has a name") {
        for (int r = P2P_DISCONNECT_NONE + 1;
             r < P2P_DISCONNECT_REASON_COUNT; r++) {
            const char *name =
                p2p_disconnect_reason_name((enum p2p_disconnect_reason)r);
            ASSERT(name != NULL);
            ASSERT(name[0] != '\0');
            ASSERT(strcmp(name, "unknown") != 0);
        }
        for (int s = P2P_DISCONNECT_SOURCE_UNKNOWN + 1;
             s < P2P_DISCONNECT_SOURCE_COUNT; s++) {
            const char *name =
                p2p_disconnect_source_name((enum p2p_disconnect_source)s);
            ASSERT(name != NULL);
            ASSERT(name[0] != '\0');
            ASSERT(strcmp(name, "unknown") != 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* One emitted line per reason, each carrying that reason's own name — the
 * pairing property a reader depends on when counting opens against closes. */
static int test_each_reason_emits_one_named_line(void)
{
    int failures = 0;
    TEST("peer_disconnect_log: each reason emits exactly one named line") {
        struct p2p_node *n = make_node("[2001:db8::1]:8033", 3, false,
                                        PEER_HANDSHAKE_COMPLETE, 170020, 9);
        ASSERT(n != NULL);
        for (int r = P2P_DISCONNECT_NONE + 1;
             r < P2P_DISCONNECT_REASON_COUNT; r++) {
            char buf[2048];
            char want[128];
            ASSERT(capture_close_line(
                n, "peer_disconnected", (enum p2p_disconnect_reason)r,
                P2P_DISCONNECT_SOURCE_SOCKET, buf, sizeof(buf)));
            snprintf(want, sizeof(want), "\"reason\":\"%s\"",
                     p2p_disconnect_reason_name(
                         (enum p2p_disconnect_reason)r));
            ASSERT(contains(buf, want));
            ASSERT(contains(buf, "\"event\":\"peer_disconnected\","));
            /* One line, never two, never zero. */
            const char *nl = strchr(buf, '\n');
            ASSERT(nl != NULL);
            ASSERT(nl[1] == '\0');
        }
        free(n);
        PASS();
    } _test_next:;
    return failures;
}

/* The timeout incidents ride their own event names so the terminal
 * "peer_disconnected" record stays unique and countable. */
static int test_timeout_events_are_distinct(void)
{
    int failures = 0;
    TEST("peer_disconnect_log: timeout lines do not impersonate the terminal line") {
        struct p2p_node *n = make_node("192.0.2.5:8033", 21, false,
                                        PEER_CONNECTING, 0, 95);
        ASSERT(n != NULL);
        char buf[2048];
        ASSERT(capture_close_line(n, "peer_handshake_timeout",
                                  P2P_DISCONNECT_HANDSHAKE_TIMEOUT,
                                  P2P_DISCONNECT_SOURCE_DIAL_SCHEDULER,
                                  buf, sizeof(buf)));
        ASSERT(contains(buf, "\"event\":\"peer_handshake_timeout\","));
        ASSERT(!contains(buf, "\"event\":\"peer_disconnected\","));
        ASSERT(contains(buf, "\"state\":\"connecting\""));

        ASSERT(capture_close_line(n, "peer_connect_timeout",
                                  P2P_DISCONNECT_CONNECT_TIMEOUT,
                                  P2P_DISCONNECT_SOURCE_DIAL_SCHEDULER,
                                  buf, sizeof(buf)));
        ASSERT(contains(buf, "\"event\":\"peer_connect_timeout\","));
        ASSERT(contains(buf, "\"reason\":\"connect_timeout\""));
        free(n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_addr_is_json_escaped(void)
{
    int failures = 0;
    TEST("peer_disconnect_log: a hostile addr name cannot break the JSON") {
        struct p2p_node *n = make_node("evil\"peer\\name", 5, false,
                                        PEER_CONNECTED, 0, 1);
        ASSERT(n != NULL);
        char buf[2048];
        ASSERT(capture_close_line(n, "peer_disconnected",
                                  P2P_DISCONNECT_IO_ERROR,
                                  P2P_DISCONNECT_SOURCE_SOCKET,
                                  buf, sizeof(buf)));
        ASSERT(contains(buf, "\"addr\":\"evil\\\"peer\\\\name\""));
        /* Still one line, and the fields after addr survived. */
        ASSERT(contains(buf, "\"reason\":\"io_error\""));
        const char *nl = strchr(buf, '\n');
        ASSERT(nl != NULL);
        ASSERT(nl[1] == '\0');
        free(n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_null_node_is_inert(void)
{
    int failures = 0;
    TEST("peer_disconnect_log: NULL node / NULL event emit nothing") {
        char buf[512];
        ASSERT(capture_close_line(NULL, "peer_disconnected",
                                  P2P_DISCONNECT_IO_ERROR,
                                  P2P_DISCONNECT_SOURCE_SOCKET,
                                  buf, sizeof(buf)));
        ASSERT(buf[0] == '\0');
        struct p2p_node *n = make_node("192.0.2.7:8033", 1, false,
                                        PEER_CONNECTED, 0, 1);
        ASSERT(n != NULL);
        ASSERT(capture_close_line(n, NULL, P2P_DISCONNECT_IO_ERROR,
                                  P2P_DISCONNECT_SOURCE_SOCKET,
                                  buf, sizeof(buf)));
        ASSERT(buf[0] == '\0');
        free(n);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Prong B: no removal path is silent ────────────────────────────── */

/* Walk up from the test binary to the tree holding the Makefile AND the two
 * net sources this lane owns, so the scan hits the right files regardless of
 * the cwd the suite runs in. Bounded walk. */
#define CONNMAN_REL "lib/net/src/connman.c"
#define NETSRC_REL  "lib/net/src/net.c"

static const char *repo_root(void)
{
    static char root[PATH_MAX];
    static int cached = 0;
    if (cached) return root[0] ? root : NULL;

    char exe[PATH_MAX];
    if (!os_proc_exe_path(exe, sizeof(exe))) {
        cached = 1; root[0] = '\0'; return NULL;
    }

    for (int depth = 0; depth < 8; depth++) {
        char *slash = strrchr(exe, '/');
        if (!slash || slash == exe) break;
        *slash = '\0';

        char probe[PATH_MAX];
        struct stat st;
        if (snprintf(probe, sizeof(probe), "%s/Makefile", exe) >= (int)sizeof(probe))
            break;
        if (stat(probe, &st) != 0) continue;
        if (snprintf(probe, sizeof(probe), "%s/%s", exe, CONNMAN_REL) >= (int)sizeof(probe))
            break;
        if (stat(probe, &st) != 0) continue;

        if (snprintf(root, sizeof(root), "%s", exe) >= (int)sizeof(root)) break;
        cached = 1;
        return root;
    }
    cached = 1; root[0] = '\0';
    return NULL;
}

static char *slurp(const char *rel)
{
    const char *root = repo_root();
    if (!root) return NULL;
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", root, rel) >= (int)sizeof(path))
        return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long len = ftell(f);
    if (len <= 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)len, f);
    fclose(f);
    buf[got] = '\0';
    return buf;
}

static size_t count_occurrences(const char *hay, const char *needle)
{
    size_t count = 0;
    size_t nlen = strlen(needle);
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += nlen)
        count++;
    return count;
}

static int test_sweep_is_the_only_removal_and_it_logs(void)
{
    int failures = 0;
    TEST("peer_disconnect_log: the nodes[] removal path emits the terminal line") {
        char *src = slurp(CONNMAN_REL);
        ASSERT(src != NULL);

        /* One removal site. If a second appears, this assertion is the
         * prompt to give it a terminal line too rather than let peers start
         * vanishing silently again. */
        ASSERT(count_occurrences(src, "cm->manager.num_nodes--") == 1);

        const char *removal = strstr(src, "cm->manager.num_nodes--");
        ASSERT(removal != NULL);
        const char *emit =
            strstr(src, "p2p_log_peer_close(node, \"peer_disconnected\"");
        ASSERT(emit != NULL);
        /* Emitted before the node is unlinked, and before the forced
         * PEER_DISCONNECTED overwrite, so the line reports the state the
         * session actually reached. */
        ASSERT(emit < removal);
        const char *forced = strstr(src, "node->state = PEER_DISCONNECTED;");
        ASSERT(forced != NULL);
        ASSERT(emit < forced);

        /* The only socket close in connman belongs to that same sweep. */
        ASSERT(count_occurrences(src, "p2p_node_close_socket(") == 1);
        ASSERT(strstr(src, "p2p_node_close_socket(") > emit);

        /* Both timeout incidents are machine-readable, and the free-form
         * printf they replaced is gone. */
        ASSERT(count_occurrences(src, "\"peer_handshake_timeout\"") == 1);
        ASSERT(count_occurrences(src, "\"peer_connect_timeout\"") == 1);
        ASSERT(!contains(src, "handshake timeout after"));

        free(src);
        PASS();
    } _test_next:;
    return failures;
}

static int test_teardown_path_is_not_silent(void)
{
    int failures = 0;
    TEST("peer_disconnect_log: shutdown teardown closes the log record too") {
        char *src = slurp(NETSRC_REL);
        ASSERT(src != NULL);

        const char *free_fn = strstr(src, "void net_manager_free(");
        ASSERT(free_fn != NULL);
        const char *emit = strstr(free_fn, "p2p_log_peer_close(node,");
        ASSERT(emit != NULL);
        const char *node_free = strstr(free_fn, "p2p_node_free(node)");
        ASSERT(node_free != NULL);
        ASSERT(emit < node_free);

        /* Both directions publish an open line, so opens and closes pair.
         * The needles carry the source's own backslash escapes — these live
         * inside a C string literal in net.c, not as bare quotes. */
        ASSERT(count_occurrences(src, "\\\"inbound\\\":false") >= 1);
        ASSERT(count_occurrences(src, "\\\"inbound\\\":true") >= 1);
        ASSERT(count_occurrences(
                   src, "log_jsonf(LOG_JSON_INFO, \"peer_connected\",") == 2);

        free(src);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ────────────────────────────────────────────── */

int test_peer_disconnect_log(void);

int test_peer_disconnect_log(void)
{
    int failures = 0;

    failures += test_close_line_shape();
    failures += test_inbound_direction_recorded();
    failures += test_every_reason_is_named();
    failures += test_each_reason_emits_one_named_line();
    failures += test_timeout_events_are_distinct();
    failures += test_addr_is_json_escaped();
    failures += test_null_node_is_inert();
    failures += test_sweep_is_the_only_removal_and_it_logs();
    failures += test_teardown_path_is_not_silent();

    return failures;
}
