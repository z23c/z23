/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "json/json.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/peers_projection.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PP_CHECK(label, cond) do { \
    bool _ok = (cond); \
    printf("peers_projection: %s... %s\n", (label), _ok ? "OK" : "FAIL"); \
    if (!_ok) failures++; \
} while (0)


static void fill_ip(uint8_t ip[16], uint8_t tail)
{
    memset(ip, 0, 16);
    ip[10] = 0xff;
    ip[11] = 0xff;
    ip[12] = 203;
    ip[13] = 0;
    ip[14] = 113;
    ip[15] = tail;
}

static bool append_observed(event_log_t *log, const uint8_t ip[16],
                            uint16_t port, uint64_t services,
                            uint32_t seen, int32_t height)
{
    struct ev_peer_observed ev;
    uint8_t payload[EV_PEER_OBSERVED_FIXED_LEN + EV_PEER_ONION_MAX];
    size_t len = 0;
    memset(&ev, 0, sizeof(ev));
    memcpy(ev.ip_v4_or_v6, ip, 16);
    ev.port = port;
    ev.services_bitmap = services;
    ev.observed_unix = seen;
    ev.height_hint = height;
    if (!ev_peer_observed_serialize(&ev, payload, sizeof(payload), &len))
        return false;
    return event_log_append(log, EV_PEER_OBSERVED, payload, len) != UINT64_MAX;
}

static bool append_dropped(event_log_t *log, const uint8_t ip[16],
                           uint16_t port)
{
    struct ev_peer_dropped ev;
    uint8_t payload[EV_PEER_DROPPED_LEN];
    memset(&ev, 0, sizeof(ev));
    memcpy(ev.ip_v4_or_v6, ip, 16);
    ev.port = port;
    ev.reason = 1;
    if (!ev_peer_dropped_serialize(&ev, payload))
        return false;
    return event_log_append(log, EV_PEER_DROPPED,
                            payload, sizeof(payload)) != UINT64_MAX;
}

static bool append_session(event_log_t *log, const uint8_t ip[16],
                           uint16_t port, uint64_t bytes_in, uint64_t bytes_out,
                           uint64_t headers, uint64_t blocks, uint32_t bw,
                           int64_t latency_us, int64_t last_useful)
{
    struct ev_peer_session_closed ev;
    uint8_t payload[EV_PEER_SESSION_CLOSED_LEN];
    memset(&ev, 0, sizeof(ev));
    memcpy(ev.ip_v4_or_v6, ip, 16);
    ev.port = port;
    ev.reason = 0;
    ev.duration_secs = 42;
    ev.bytes_in = bytes_in;
    ev.bytes_out = bytes_out;
    ev.headers_delivered = headers;
    ev.blocks_delivered = blocks;
    ev.bandwidth_score = bw;
    ev.avg_latency_us = latency_us;
    ev.last_useful_time = last_useful;
    if (!ev_peer_session_closed_serialize(&ev, payload))
        return false;
    return event_log_append(log, EV_PEER_SESSION_CLOSED,
                            payload, sizeof(payload)) != UINT64_MAX;
}

static bool append_fork(event_log_t *log, int64_t height, int64_t observed,
                        uint32_t num_clusters, uint32_t ca, uint32_t cb,
                        const char *ha, const char *hb)
{
    struct ev_net_fork_observed ev;
    uint8_t payload[EV_NET_FORK_OBSERVED_FIXED_LEN +
                    2 * EV_NET_FORK_TIP_HEX_MAX];
    size_t len = 0;
    memset(&ev, 0, sizeof(ev));
    ev.height = height;
    ev.observed_unix = observed;
    ev.num_clusters = num_clusters;
    ev.count_a = ca;
    ev.count_b = cb;
    if (ha) { size_t n = strlen(ha); memcpy(ev.tip_hash_a, ha, n);
              ev.hash_a_len = (uint8_t)n; }
    if (hb) { size_t n = strlen(hb); memcpy(ev.tip_hash_b, hb, n);
              ev.hash_b_len = (uint8_t)n; }
    if (!ev_net_fork_observed_serialize(&ev, payload, sizeof(payload), &len))
        return false;
    return event_log_append(log, EV_NET_FORK_OBSERVED, payload, len)
           != UINT64_MAX;
}

static int t_payload_roundtrip(void)
{
    int failures = 0;
    uint8_t payload[EV_PEER_OBSERVED_FIXED_LEN + EV_PEER_ONION_MAX];
    struct ev_peer_observed in, out;
    size_t len = 0;
    memset(&in, 0, sizeof(in));
    fill_ip(in.ip_v4_or_v6, 9);
    in.port = 8033;
    in.services_bitmap = 0xdeadbeefULL;
    in.observed_unix = 1700000000u;
    in.height_hint = 1234;
    in.is_onion = 1;
    in.onion_len = 11;
    memcpy(in.onion, "abcde.onion", 11);
    PP_CHECK("observed serialize",
             ev_peer_observed_serialize(&in, payload, sizeof(payload),
                                        &len));
    PP_CHECK("observed parse",
             ev_peer_observed_parse(payload, len, &out));
    PP_CHECK("observed roundtrip",
             memcmp(in.ip_v4_or_v6, out.ip_v4_or_v6, 16) == 0 &&
             out.port == in.port &&
             out.services_bitmap == in.services_bitmap &&
             out.observed_unix == in.observed_unix &&
             out.height_hint == in.height_hint &&
             out.is_onion == in.is_onion &&
             out.onion_len == in.onion_len &&
             memcmp(in.onion, out.onion, in.onion_len) == 0);

    struct ev_peer_dropped din, dout;
    uint8_t dropped[EV_PEER_DROPPED_LEN];
    memset(&din, 0, sizeof(din));
    fill_ip(din.ip_v4_or_v6, 10);
    din.port = 9033;
    din.reason = 3;
    PP_CHECK("dropped serialize",
             ev_peer_dropped_serialize(&din, dropped));
    PP_CHECK("dropped parse",
             ev_peer_dropped_parse(dropped, sizeof(dropped), &dout));
    PP_CHECK("dropped roundtrip",
             memcmp(din.ip_v4_or_v6, dout.ip_v4_or_v6, 16) == 0 &&
             dout.port == din.port && dout.reason == din.reason);

    struct ev_peer_session_closed sin, sout;
    uint8_t sbuf[EV_PEER_SESSION_CLOSED_LEN];
    memset(&sin, 0, sizeof(sin));
    fill_ip(sin.ip_v4_or_v6, 20);
    sin.port = 8033;
    sin.reason = 1;
    sin.duration_secs = 3600;
    sin.bytes_in = 0x1122334455667788ULL;
    sin.bytes_out = 0x8877665544332211ULL;
    sin.headers_delivered = 987654;
    sin.blocks_delivered = 123;
    sin.bandwidth_score = 200;
    sin.avg_latency_us = -55; /* sign round-trip */
    sin.last_useful_time = 1700000123LL;
    PP_CHECK("session serialize",
             ev_peer_session_closed_serialize(&sin, sbuf));
    PP_CHECK("session parse",
             ev_peer_session_closed_parse(sbuf, sizeof(sbuf), &sout));
    PP_CHECK("session roundtrip",
             memcmp(sin.ip_v4_or_v6, sout.ip_v4_or_v6, 16) == 0 &&
             sout.port == sin.port && sout.reason == sin.reason &&
             sout.duration_secs == sin.duration_secs &&
             sout.bytes_in == sin.bytes_in &&
             sout.bytes_out == sin.bytes_out &&
             sout.headers_delivered == sin.headers_delivered &&
             sout.blocks_delivered == sin.blocks_delivered &&
             sout.bandwidth_score == sin.bandwidth_score &&
             sout.avg_latency_us == sin.avg_latency_us &&
             sout.last_useful_time == sin.last_useful_time);
    PP_CHECK("session rejects short", !ev_peer_session_closed_parse(sbuf,
             sizeof(sbuf) - 1, &sout));

    struct ev_net_fork_observed fin, fout;
    uint8_t fbuf[EV_NET_FORK_OBSERVED_FIXED_LEN + 2 * EV_NET_FORK_TIP_HEX_MAX];
    size_t flen = 0;
    memset(&fin, 0, sizeof(fin));
    fin.height = 3176325;
    fin.observed_unix = 1700000000LL;
    fin.num_clusters = 3;
    fin.count_a = 5;
    fin.count_b = 4;
    memset(fin.tip_hash_a, 'a', 64); fin.hash_a_len = 64;
    memset(fin.tip_hash_b, 'b', 64); fin.hash_b_len = 64;
    PP_CHECK("fork serialize",
             ev_net_fork_observed_serialize(&fin, fbuf, sizeof(fbuf), &flen));
    PP_CHECK("fork parse", ev_net_fork_observed_parse(fbuf, flen, &fout));
    PP_CHECK("fork roundtrip",
             fout.height == fin.height && fout.observed_unix == fin.observed_unix &&
             fout.num_clusters == fin.num_clusters &&
             fout.count_a == fin.count_a && fout.count_b == fin.count_b &&
             fout.hash_a_len == 64 && fout.hash_b_len == 64 &&
             memcmp(fout.tip_hash_a, fin.tip_hash_a, 64) == 0 &&
             memcmp(fout.tip_hash_b, fin.tip_hash_b, 64) == 0);
    return failures;
}

/* Reputation round-trips through fold + accumulates + survives reopen + a
 * later re-observation must NOT wipe it. */
static int t_reputation_roundtrip(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    uint8_t ip[16];
    test_make_tmpdir(dir, sizeof(dir), "peers_projection", "reputation");
    test_projection_paths(dir, "peers", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    fill_ip(ip, 55);
    event_log_t *log = event_log_open(elog_path);
    peers_projection_t *p = peers_projection_open(proj_path, log);

    /* Two banked sessions for the same peer: headers/blocks accumulate,
     * sessions_count increments, last_useful_time takes the MAX, and
     * bandwidth_score/latency reflect the latest close. */
    PP_CHECK("append session 1",
             append_session(log, ip, 8033, 1000, 500, 100, 5, 180, 12000, 1000));
    PP_CHECK("append session 2",
             append_session(log, ip, 8033, 2000, 900, 60, 3, 220, 9000, 2000));
    PP_CHECK("catch up sessions", peers_projection_catch_up(p) != UINT64_MAX);

    struct peer_reputation rep;
    PP_CHECK("get reputation",
             peers_projection_get_reputation(p, ip, 8033, &rep));
    PP_CHECK("sessions_count accumulates", rep.sessions_count == 2);
    PP_CHECK("headers accumulate", rep.headers_delivered == 160);
    PP_CHECK("blocks accumulate", rep.blocks_delivered == 8);
    PP_CHECK("bandwidth latest wins", rep.bandwidth_score == 220);
    PP_CHECK("latency latest wins", rep.avg_latency_us == 9000);
    PP_CHECK("last_useful is max", rep.last_useful_time == 2000);

    /* A later observation must PRESERVE the banked reputation (UPSERT, not
     * INSERT OR REPLACE). */
    PP_CHECK("append later observed",
             append_observed(log, ip, 8033, 9, 1700000005u, 999));
    PP_CHECK("catch up observed", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("reputation survives re-observe",
             peers_projection_get_reputation(p, ip, 8033, &rep) &&
             rep.sessions_count == 2 && rep.headers_delivered == 160 &&
             rep.bandwidth_score == 220);

    /* Survives a close + reopen (cursor persisted, addresses table on disk). */
    peers_projection_close(p);
    event_log_close(log);
    log = event_log_open(elog_path);
    p = peers_projection_open(proj_path, log);
    PP_CHECK("catch up after reopen", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("reputation survives reopen",
             peers_projection_get_reputation(p, ip, 8033, &rep) &&
             rep.sessions_count == 2 && rep.headers_delivered == 160 &&
             rep.blocks_delivered == 8 && rep.bandwidth_score == 220 &&
             rep.last_useful_time == 2000);

    peers_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Missing / never-banked reputation reads all-zero (false), and a corrupt
 * session payload aborts its batch WITHOUT corrupting prior reputation. */
static int t_reputation_fallback_clean(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    uint8_t ip[16], other[16];
    test_make_tmpdir(dir, sizeof(dir), "peers_projection", "repfallback");
    test_projection_paths(dir, "peers", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    fill_ip(ip, 66);
    fill_ip(other, 67);
    event_log_t *log = event_log_open(elog_path);
    peers_projection_t *p = peers_projection_open(proj_path, log);

    struct peer_reputation rep;
    memset(&rep, 0xAB, sizeof(rep));
    PP_CHECK("unknown reputation false + zeroed",
             !peers_projection_get_reputation(p, ip, 8033, &rep) &&
             rep.bandwidth_score == 0 && rep.sessions_count == 0);

    /* Observed-only peer: row exists but reputation is clean zero (download
     * seed would no-op) — exactly today's behavior. */
    PP_CHECK("append observed only",
             append_observed(log, ip, 8033, 1, 100, 10));
    PP_CHECK("catch up", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("observed-only reputation is zero",
             !peers_projection_get_reputation(p, ip, 8033, &rep) ||
             (rep.bandwidth_score == 0 && rep.sessions_count == 0));

    /* Bank a good session, then append a CORRUPT (truncated) session payload:
     * the batch aborts (UINT64_MAX) but the good reputation is untouched. */
    PP_CHECK("append good session",
             append_session(log, other, 8033, 1, 1, 50, 2, 150, 5000, 4242));
    PP_CHECK("catch up good", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("good banked",
             peers_projection_get_reputation(p, other, 8033, &rep) &&
             rep.bandwidth_score == 150 && rep.headers_delivered == 50);

    uint8_t bad[EV_PEER_SESSION_CLOSED_LEN - 4] = {0};
    PP_CHECK("append corrupt session",
             event_log_append(log, EV_PEER_SESSION_CLOSED, bad, sizeof(bad))
             != UINT64_MAX);
    PP_CHECK("corrupt batch aborts",
             peers_projection_catch_up(p) == UINT64_MAX);
    PP_CHECK("good reputation intact after corrupt",
             peers_projection_get_reputation(p, other, 8033, &rep) &&
             rep.bandwidth_score == 150 && rep.headers_delivered == 50);

    peers_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Session + fork ledgers append durably and honor the delete-oldest cap. */
static int t_ledger_retention(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    uint8_t ip[16];
    test_make_tmpdir(dir, sizeof(dir), "peers_projection", "retention");
    test_projection_paths(dir, "peers", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    fill_ip(ip, 88);
    event_log_t *log = event_log_open(elog_path);
    peers_projection_t *p = peers_projection_open(proj_path, log);

    peers_projection_test_set_retention_caps(3, 2);

    for (int i = 0; i < 5; i++)
        PP_CHECK("append session (retention)",
                 append_session(log, ip, (uint16_t)(8000 + i), 1, 1,
                                (uint64_t)i, 0, 100, 1000, 100 + i));
    for (int i = 0; i < 4; i++)
        PP_CHECK("append fork (retention)",
                 append_fork(log, 1000 + i, 2000 + i, 2, 2, 2, "aaaa", "bbbb"));
    PP_CHECK("catch up ledgers", peers_projection_catch_up(p) != UINT64_MAX);

    PP_CHECK("peer_sessions capped to 3",
             peers_projection_test_ledger_count(p, "peer_sessions") == 3);
    PP_CHECK("fork_events capped to 2",
             peers_projection_test_ledger_count(p, "fork_events") == 2);

    peers_projection_test_reset_retention_caps();
    peers_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_open_close_clean(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    test_make_tmpdir(dir, sizeof(dir), "peers_projection", "open");
    test_projection_paths(dir, "peers", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    event_log_t *log = event_log_open(elog_path);
    peers_projection_t *p = peers_projection_open(proj_path, log);
    PP_CHECK("open handles", log && p);
    PP_CHECK("empty count", peers_projection_count(p) == 0);
    peers_projection_close(p);
    event_log_close(log);
    log = event_log_open(elog_path);
    p = peers_projection_open(proj_path, log);
    PP_CHECK("reopen handles", log && p);
    PP_CHECK("reopen empty count", peers_projection_count(p) == 0);
    peers_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_add_drop_replay(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    uint8_t ip[16];
    uint64_t services = 0;
    int64_t seen = 0;
    int32_t height = 0;
    test_make_tmpdir(dir, sizeof(dir), "peers_projection", "adddrop");
    test_projection_paths(dir, "peers", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    fill_ip(ip, 42);
    event_log_t *log = event_log_open(elog_path);
    peers_projection_t *p = peers_projection_open(proj_path, log);
    PP_CHECK("append observed",
             append_observed(log, ip, 8033, 9, 1700000001u, 321));
    PP_CHECK("catch up observed", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("count after observed", peers_projection_count(p) == 1);
    PP_CHECK("get observed",
             peers_projection_get(p, ip, 8033, &services, &seen, &height) &&
             services == 9 && seen == 1700000001LL && height == 321);
    PP_CHECK("idempotent catch up", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("count still one", peers_projection_count(p) == 1);
    PP_CHECK("append dropped", append_dropped(log, ip, 8033));
    PP_CHECK("catch up dropped", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("count after dropped", peers_projection_count(p) == 0);
    PP_CHECK("get absent", !peers_projection_get(p, ip, 8033, NULL, NULL, NULL));
    peers_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_replace_collision(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    uint8_t ip[16];
    uint64_t services = 0;
    int64_t seen = 0;
    int32_t height = 0;
    test_make_tmpdir(dir, sizeof(dir), "peers_projection", "replace");
    test_projection_paths(dir, "peers", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    fill_ip(ip, 77);
    event_log_t *log = event_log_open(elog_path);
    peers_projection_t *p = peers_projection_open(proj_path, log);
    append_observed(log, ip, 8033, 1, 100, 10);
    append_observed(log, ip, 8033, 2, 200, 20);
    PP_CHECK("catch up replace", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("replace count one", peers_projection_count(p) == 1);
    PP_CHECK("replace value wins",
             peers_projection_get(p, ip, 8033, &services, &seen, &height) &&
             services == 2 && seen == 200 && height == 20);
    peers_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── node census (EV_NODE_CENSUS_OBSERVED) ──────────────────────────────── */

static int t_census_payload_roundtrip(void)
{
    int failures = 0;
    struct ev_node_census_observed in, out;
    uint8_t buf[EV_NODE_CENSUS_OBSERVED_FIXED_LEN + EV_CENSUS_UA_MAX];
    size_t len = 0;
    memset(&in, 0, sizeof(in));
    fill_ip(in.ip_v4_or_v6, 30);
    in.port = 8033;
    in.source = EV_CENSUS_SOURCE_CRAWLER;
    in.success = 1;
    in.ua_overflow = 1;
    in.protocol_version = 170008;
    in.services = 0x0123456789abcdefULL;
    in.reported_height = 3176325;
    in.observed_unix = 1700000000LL;
    const char *ua = "/MagicBean:2.1.1-1/";
    in.ua_len = (uint16_t)strlen(ua);
    memcpy(in.user_agent, ua, in.ua_len);
    PP_CHECK("census serialize",
             ev_node_census_observed_serialize(&in, buf, sizeof(buf), &len));
    PP_CHECK("census len is fixed+ua",
             len == EV_NODE_CENSUS_OBSERVED_FIXED_LEN + in.ua_len);
    PP_CHECK("census parse", ev_node_census_observed_parse(buf, len, &out));
    PP_CHECK("census roundtrip",
             memcmp(in.ip_v4_or_v6, out.ip_v4_or_v6, 16) == 0 &&
             out.port == in.port && out.source == in.source &&
             out.success == in.success && out.ua_overflow == in.ua_overflow &&
             out.protocol_version == in.protocol_version &&
             out.services == in.services &&
             out.reported_height == in.reported_height &&
             out.observed_unix == in.observed_unix &&
             out.ua_len == in.ua_len &&
             memcmp(out.user_agent, in.user_agent, in.ua_len) == 0);
    /* short payload rejected; ua_len > cap rejected on serialize. */
    PP_CHECK("census rejects short",
             !ev_node_census_observed_parse(buf,
                 EV_NODE_CENSUS_OBSERVED_FIXED_LEN - 1, &out));
    struct ev_node_census_observed over = in;
    over.ua_len = EV_CENSUS_UA_MAX + 1;
    PP_CHECK("census serialize rejects over-cap ua_len",
             !ev_node_census_observed_serialize(&over, buf, sizeof(buf), &len));
    /* a length-mismatched buffer is rejected on parse. */
    PP_CHECK("census rejects len mismatch",
             !ev_node_census_observed_parse(buf, len + 1, &out));
    return failures;
}

/* Success upserts (first_seen stable, success count accumulates, latest UA/
 * proto/height win); a failed dial only bumps an existing row's fail count and
 * NEVER inserts; the time-series appends one row per success only. */
static int t_census_fold_upsert(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    uint8_t ip1[16], ip2[16];
    test_make_tmpdir(dir, sizeof(dir), "peers_projection", "census_fold");
    test_projection_paths(dir, "peers", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    fill_ip(ip1, 100);
    fill_ip(ip2, 101);
    event_log_t *log = event_log_open(elog_path);
    peers_projection_t *p = peers_projection_open(proj_path, log);
    peers_projection_set_event_log(log);

    PP_CHECK("emit success #1",
             peers_projection_emit_census_observed(ip1, 8033,
                 EV_CENSUS_SOURCE_PEER, true, "/MagicBean:1/", 170008, 1,
                 1000, 1700000000LL));
    PP_CHECK("catch up #1", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("census count 1", peers_projection_census_count(p) == 1);

    struct census_row_view row;
    char uabuf[300];
    PP_CHECK("read row #1",
             peers_projection_test_census_row(p, ip1, 8033, &row, uabuf,
                                              sizeof(uabuf)));
    PP_CHECK("first_seen set", row.first_seen == 1700000000LL);
    PP_CHECK("dial_success 1", row.dial_success_count == 1);
    PP_CHECK("dial_fail 0", row.dial_fail_count == 0);
    PP_CHECK("last_success set", row.last_success == 1700000000LL);
    PP_CHECK("proto #1", row.protocol_version == 170008);
    PP_CHECK("source peer", row.source == EV_CENSUS_SOURCE_PEER);
    PP_CHECK("ua #1", strcmp(uabuf, "/MagicBean:1/") == 0);

    /* re-observe (success) with newer identity: upsert, first_seen stable. */
    PP_CHECK("emit success #2",
             peers_projection_emit_census_observed(ip1, 8033,
                 EV_CENSUS_SOURCE_CRAWLER, true, "/MagicBean:2/", 170009, 3,
                 2000, 1700000100LL));
    PP_CHECK("catch up #2", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("census still 1 (upsert)", peers_projection_census_count(p) == 1);
    PP_CHECK("read row #2",
             peers_projection_test_census_row(p, ip1, 8033, &row, uabuf,
                                              sizeof(uabuf)));
    PP_CHECK("first_seen STABLE", row.first_seen == 1700000000LL);
    PP_CHECK("last_seen advanced", row.last_seen == 1700000100LL);
    PP_CHECK("dial_success 2", row.dial_success_count == 2);
    PP_CHECK("proto latest wins", row.protocol_version == 170009);
    PP_CHECK("height latest wins", row.last_reported_height == 2000);
    PP_CHECK("ua latest wins", strcmp(uabuf, "/MagicBean:2/") == 0);
    PP_CHECK("source now crawler", row.source == EV_CENSUS_SOURCE_CRAWLER);

    /* failed dial: bumps fail count only, preserves identity + first_seen. */
    PP_CHECK("emit fail (known node)",
             peers_projection_emit_census_observed(ip1, 8033,
                 EV_CENSUS_SOURCE_CRAWLER, false, "", 0, 0, -1, 1700000200LL));
    PP_CHECK("catch up fail", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("census still 1 after fail",
             peers_projection_census_count(p) == 1);
    PP_CHECK("read row #3",
             peers_projection_test_census_row(p, ip1, 8033, &row, uabuf,
                                              sizeof(uabuf)));
    PP_CHECK("dial_fail 1", row.dial_fail_count == 1);
    PP_CHECK("dial_success unchanged", row.dial_success_count == 2);
    PP_CHECK("first_seen still stable", row.first_seen == 1700000000LL);
    PP_CHECK("last_success unchanged", row.last_success == 1700000100LL);
    PP_CHECK("ua preserved on fail", strcmp(uabuf, "/MagicBean:2/") == 0);

    /* failed dial for a NEVER-SEEN node must NOT insert a row. */
    PP_CHECK("emit fail (unknown node)",
             peers_projection_emit_census_observed(ip2, 8033,
                 EV_CENSUS_SOURCE_CRAWLER, false, "", 0, 0, -1, 1700000300LL));
    PP_CHECK("catch up fail unknown", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("fail never inserts", peers_projection_census_count(p) == 1);
    PP_CHECK("unknown row absent",
             !peers_projection_test_census_row(p, ip2, 8033, NULL, NULL, 0));

    /* now a success for ip2 creates the 2nd row. */
    PP_CHECK("emit success ip2",
             peers_projection_emit_census_observed(ip2, 8033,
                 EV_CENSUS_SOURCE_CRAWLER, true, "/MagicBean:2/", 170009, 4,
                 2100, 1700000400LL));
    PP_CHECK("catch up ip2", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("census count 2", peers_projection_census_count(p) == 2);

    /* the time-series appended exactly one row per SUCCESS (3 successes). */
    PP_CHECK("observations == 3 (successes only)",
             peers_projection_test_ledger_count(p, "census_observations") == 3);

    peers_projection_set_event_log(NULL);
    peers_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Pedantic UA gate: control/high bytes are rejected (no row, no crash); an
 * over-long UA is stored truncated WITH the ua_overflow flag (never silently). */
static int t_census_pedantic_ua(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    uint8_t ip1[16], ip2[16], ip3[16];
    test_make_tmpdir(dir, sizeof(dir), "peers_projection", "census_ua");
    test_projection_paths(dir, "peers", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    fill_ip(ip1, 110);
    fill_ip(ip2, 111);
    fill_ip(ip3, 112);
    event_log_t *log = event_log_open(elog_path);
    peers_projection_t *p = peers_projection_open(proj_path, log);
    peers_projection_set_event_log(log);

    /* control byte (0x01) → malformed → rejected, no row.
     * (String split after \x01 so the greedy hex escape doesn't swallow
     * the following hex-digit-looking letters "Bea" into one huge
     * out-of-range escape — adjacent literals concatenate in C.) */
    PP_CHECK("control-byte UA rejected",
             !peers_projection_emit_census_observed(ip1, 8033,
                 EV_CENSUS_SOURCE_CRAWLER, true, "/Magic\x01" "Bean/", 1, 1, 1,
                 1700000000LL));
    /* high byte (0xFF) → malformed → rejected. */
    PP_CHECK("high-byte UA rejected",
             !peers_projection_emit_census_observed(ip2, 8033,
                 EV_CENSUS_SOURCE_CRAWLER, true, "/Magic\xff" "Bean/", 1, 1, 1,
                 1700000000LL));
    PP_CHECK("catch up (no rows)", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("malformed produced no rows",
             peers_projection_census_count(p) == 0);

    /* over-long (400 printable chars) → accepted, truncated to cap WITH flag. */
    char big[400];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    PP_CHECK("oversized UA accepted (truncate+flag)",
             peers_projection_emit_census_observed(ip3, 8033,
                 EV_CENSUS_SOURCE_CRAWLER, true, big, 170008, 1, 500,
                 1700000000LL));
    PP_CHECK("catch up oversized", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("oversized inserted one row",
             peers_projection_census_count(p) == 1);
    struct census_row_view row;
    char uabuf[512];
    PP_CHECK("read oversized row",
             peers_projection_test_census_row(p, ip3, 8033, &row, uabuf,
                                              sizeof(uabuf)));
    PP_CHECK("ua_overflow flag set", row.ua_overflow == 1);
    PP_CHECK("ua truncated to cap (not silent)",
             strlen(uabuf) == EV_CENSUS_UA_MAX);

    /* the gate does not wedge: a normal UA still lands afterward. */
    PP_CHECK("normal UA still works after reject",
             peers_projection_emit_census_observed(ip1, 8033,
                 EV_CENSUS_SOURCE_PEER, true, "/MagicBean:ok/", 170008, 1, 1,
                 1700000000LL));
    PP_CHECK("catch up normal", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("census count 2 after normal",
             peers_projection_census_count(p) == 2);

    peers_projection_set_event_log(NULL);
    peers_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* The census_observations time-series honors its delete-oldest retention cap;
 * node_census (the durable book) is NOT capped. */
static int t_census_retention(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    uint8_t ip[16];
    test_make_tmpdir(dir, sizeof(dir), "peers_projection", "census_ret");
    test_projection_paths(dir, "peers", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    fill_ip(ip, 120);
    event_log_t *log = event_log_open(elog_path);
    peers_projection_t *p = peers_projection_open(proj_path, log);
    peers_projection_set_event_log(log);

    peers_projection_test_set_census_cap(3);
    for (int i = 0; i < 5; i++)
        PP_CHECK("emit success (retention)",
                 peers_projection_emit_census_observed(ip, (uint16_t)(9000 + i),
                     EV_CENSUS_SOURCE_CRAWLER, true, "/MagicBean:r/", 170008,
                     1, 1000 + i, 1700000000LL + i));
    PP_CHECK("catch up retention", peers_projection_catch_up(p) != UINT64_MAX);
    PP_CHECK("observations capped to 3",
             peers_projection_test_ledger_count(p, "census_observations") == 3);
    PP_CHECK("node_census NOT capped (5 distinct nodes)",
             peers_projection_census_count(p) == 5);

    peers_projection_test_reset_retention_caps();
    peers_projection_set_event_log(NULL);
    peers_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* The census dumper produces a well-formed object without crashing. */
static int t_census_dumper_smoke(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    uint8_t ip[16];
    test_make_tmpdir(dir, sizeof(dir), "peers_projection", "census_dump");
    test_projection_paths(dir, "peers", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    fill_ip(ip, 130);
    event_log_t *log = event_log_open(elog_path);
    peers_projection_t *p = peers_projection_open(proj_path, log);
    peers_projection_set_event_log(log);
    (void)peers_projection_emit_census_observed(ip, 8033,
        EV_CENSUS_SOURCE_PEER, true, "/MagicBean:dump/", 170008, 1, 4242,
        1700000000LL);
    (void)peers_projection_catch_up(p);

    struct json_value out;
    json_init(&out);
    PP_CHECK("census dump ok", census_dump_state_json(&out, NULL));
    json_free(&out);

    peers_projection_set_event_log(NULL);
    peers_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_peers_projection(void)
{
    int failures = 0;
    printf("\n=== peers_projection tests ===\n");
    failures += t_payload_roundtrip();
    failures += t_open_close_clean();
    failures += t_add_drop_replay();
    failures += t_replace_collision();
    failures += t_reputation_roundtrip();
    failures += t_reputation_fallback_clean();
    failures += t_ledger_retention();
    failures += t_census_payload_roundtrip();
    failures += t_census_fold_upsert();
    failures += t_census_pedantic_ua();
    failures += t_census_retention();
    failures += t_census_dumper_smoke();
    printf("peers_projection: %d failures\n", failures);
    return failures;
}
