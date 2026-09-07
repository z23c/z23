/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `z23 fleet link probe` — what the low-latency datagram channel between two
 * fleet boxes actually measures: round-trip microseconds, jitter, and loss.
 *
 * This is an OPERATOR AND DEVELOPER tool and it is deliberately outside the
 * node's hot path. It binds its own ephemeral socket, sends its own pings,
 * prints its numbers and exits; the node never calls it and nothing it does
 * touches consensus, block relay, or the datadir.
 *
 * Three modes, because there are three questions:
 *
 *   loopback (default) — what does this BOX cost? Two endpoints in this one
 *     process over 127.0.0.1, keyed from freshly drawn random material that
 *     never leaves the process. The number is the kernel's UDP path plus the
 *     per-packet crypto, which is the floor under every real measurement.
 *
 *   echo — hold a port open and answer pings, so a peer can measure the path.
 *
 *   probe — measure the path to a peer that is running `echo`.
 *
 * `echo` and `probe` take the shared key as an operator-supplied hex string
 * because the pairing plumbing that would hand this leaf a live Noise
 * session's material does not exist yet (docs/GAMELINK.md, "What is
 * missing"). That is stated rather than hidden: the key is visible in this
 * machine's process list while the command runs, the traffic it protects is
 * timestamps and nothing else, and it is not any other key this node holds.
 */

#include "command/native_command.h"

#include "base/hex.h"
#include "gamelink/gamelink.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/clock.h"
#include "platform/rng.h"
#include "platform/socket_compat.h"

#include <stdio.h>
#include <string.h>

#define LINK_PING_INTERVAL_MS 100
#define LINK_DEFAULT_SECONDS 2
#define LINK_MAX_SECONDS 60
#define LINK_KEY_HEX_CHARS 64

static void link_refuse(struct zcl_command_reply *reply, const char *code,
                        const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "link", false, false,
                           message, evidence);
}

static const char *link_str(const struct zcl_command_request *request,
                            const char *key)
{
    if (!request || !request->input)
        return NULL;
    const struct json_value *value = json_get(request->input, key);
    if (!value || value->type != JSON_STR)
        return NULL;
    const char *text = json_get_str(value);
    return text && text[0] ? text : NULL;
}

static int64_t link_int(const struct zcl_command_request *request,
                        const char *key, int64_t fallback)
{
    if (!request || !request->input)
        return fallback;
    const struct json_value *value = json_get(request->input, key);
    if (!value || value->type != JSON_INT)
        return fallback;
    return json_get_int(value);
}

/* The key material both ends of a probe must agree on. `hex` is a 32-byte
 * pre-shared secret for the echo/probe pair; NULL draws fresh random
 * material, which is what the loopback mode wants. */
static bool link_material(const char *hex,
                          uint8_t out[GAMELINK_MATERIAL_BYTES])
{
    memset(out, 0, GAMELINK_MATERIAL_BYTES);
    if (!hex)
        return rng_fill(out, GAMELINK_MATERIAL_BYTES);
    if (strlen(hex) != LINK_KEY_HEX_CHARS)
        return false;
    return zcl_hex_decode(hex, out, 32);
}

static void link_push_stats(struct json_value *data,
                            const struct gamelink_stats *stats)
{
    (void)json_push_kv_int(data, "rtt_us", (int64_t)stats->rtt_us);
    (void)json_push_kv_int(data, "jitter_us", (int64_t)stats->jitter_us);
    (void)json_push_kv_int(data, "loss_ppm", (int64_t)stats->loss_ppm);
    (void)json_push_kv_int(data, "sent", (int64_t)stats->sent);
    (void)json_push_kv_int(data, "recv", (int64_t)stats->recv);
    (void)json_push_kv_int(data, "dropped_old", (int64_t)stats->dropped_old);
    (void)json_push_kv_int(data, "dropped_auth", (int64_t)stats->dropped_auth);
    (void)json_push_kv_int(data, "dropped_malformed",
                           (int64_t)stats->dropped_malformed);
    (void)json_push_kv_int(data, "pings_sent", (int64_t)stats->pings_sent);
    (void)json_push_kv_int(data, "pongs_recv", (int64_t)stats->pongs_recv);
}

/* Wait for the socket to become readable, or for the deadline, whichever
 * comes first. The monotonic clock is the platform seam's, so a machine
 * whose wall clock steps does not shorten or lengthen a probe. */
static bool link_wait(const struct gamelink *link, int64_t deadline_ns,
                      int budget_ms)
{
    int64_t remaining_ns = deadline_ns - clock_now_monotonic_ns();
    if (remaining_ns <= 0)
        return false;
    int wait_ms = (int)(remaining_ns / 1000000);
    if (wait_ms > budget_ms)
        wait_ms = budget_ms;
    if (wait_ms < 1)
        wait_ms = 1;
    (void)platform_socket_wait_readable((platform_socket_t)link->socket,
                                        wait_ms);
    return true;
}

/* Ping until the deadline, answering and measuring whatever comes back. */
static void link_probe_loop(struct gamelink *link, struct gamelink *echo,
                            int64_t seconds)
{
    int64_t deadline = clock_now_monotonic_ns() + seconds * 1000000000;
    int64_t next_ping = 0;
    while (clock_now_monotonic_ns() < deadline) {
        int64_t now = clock_now_monotonic_ns();
        if (now >= next_ping) {
            (void)gamelink_ping(link);
            next_ping = now + (int64_t)LINK_PING_INTERVAL_MS * 1000000;
        }
        if (echo)
            (void)gamelink_probe_serve(echo);
        (void)gamelink_poll(link, NULL, NULL);
        if (!link_wait(link, deadline, LINK_PING_INTERVAL_MS))
            break;
    }
}

/* mode=echo: hold the port open and answer pings until the deadline. */
static void link_echo_loop(struct gamelink *echo, int64_t seconds)
{
    int64_t deadline = clock_now_monotonic_ns() + seconds * 1000000000;
    while (clock_now_monotonic_ns() < deadline) {
        (void)gamelink_probe_serve(echo);
        if (!link_wait(echo, deadline, LINK_PING_INTERVAL_MS))
            break;
    }
}

struct link_plan {
    const char *mode;
    const char *peer;
    const char *bind;
    const char *key_hex;
    int64_t seconds;
};

static bool link_read_plan(const struct zcl_command_request *request,
                           struct link_plan *plan,
                           struct zcl_command_reply *reply)
{
    plan->mode = link_str(request, "mode");
    if (!plan->mode)
        plan->mode = "loopback";
    plan->peer = link_str(request, "peer");
    plan->bind = link_str(request, "bind");
    if (!plan->bind)
        plan->bind = "127.0.0.1:0";
    plan->key_hex = link_str(request, "key");
    plan->seconds = link_int(request, "seconds", LINK_DEFAULT_SECONDS);
    if (plan->seconds < 1 || plan->seconds > LINK_MAX_SECONDS) {
        link_refuse(reply, "LINK_SECONDS_RANGE",
                    "seconds is 1 to 60", "input.seconds");
        return false;
    }
    bool remote = strcmp(plan->mode, "echo") == 0 ||
                  strcmp(plan->mode, "probe") == 0;
    if (!remote && strcmp(plan->mode, "loopback") != 0) {
        link_refuse(reply, "LINK_MODE_UNKNOWN",
                    "mode is loopback, echo or probe", "input.mode");
        return false;
    }
    if (remote && !plan->key_hex) {
        link_refuse(reply, "LINK_KEY_REQUIRED",
                    "echo and probe need the shared 32-byte key as 64 hex "
                    "characters; there is no pairing plumbing behind this "
                    "leaf yet", "input.key");
        return false;
    }
    if (strcmp(plan->mode, "probe") == 0 && !plan->peer) {
        link_refuse(reply, "LINK_PEER_REQUIRED",
                    "probe needs the peer's ip:port", "input.peer");
        return false;
    }
    return true;
}

/* mode=loopback: two endpoints in this process, so the number is this box's
 * own floor rather than a claim about a network nobody measured. */
static void link_run_loopback(const struct link_plan *plan,
                              struct zcl_command_reply *reply)
{
    uint8_t material[GAMELINK_MATERIAL_BYTES];
    if (!link_material(NULL, material)) {
        link_refuse(reply, "LINK_RANDOM_UNAVAILABLE",
                    "the platform random source refused", "rng");
        return;
    }
    struct gamelink echo = {.socket = -1};
    struct gamelink probe = {.socket = -1};
    enum gamelink_status status = gamelink_open(
        &echo, material, sizeof material, false, plan->bind, NULL, NULL);
    if (status != GAMELINK_OK) {
        link_refuse(reply, "LINK_OPEN_FAILED", gamelink_status_label(status),
                    "bind");
        return;
    }
    char endpoint[64];
    (void)snprintf(endpoint, sizeof endpoint, "127.0.0.1:%u",
                   (unsigned)echo.local_port);
    status = gamelink_open(&probe, material, sizeof material, true, plan->bind,
                           endpoint, NULL);
    memset(material, 0, sizeof material);
    if (status != GAMELINK_OK) {
        gamelink_close(&echo);
        link_refuse(reply, "LINK_OPEN_FAILED", gamelink_status_label(status),
                    "peer");
        return;
    }
    link_probe_loop(&probe, &echo, plan->seconds);
    struct gamelink_stats stats;
    gamelink_stats(&probe, &stats);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet_link_probe.v1");
    (void)json_push_kv_str(&reply->data, "mode", "loopback");
    (void)json_push_kv_int(&reply->data, "local_port",
                           (int64_t)probe.local_port);
    (void)json_push_kv_int(&reply->data, "peer_port", (int64_t)echo.local_port);
    link_push_stats(&reply->data, &stats);
    gamelink_close(&probe);
    gamelink_close(&echo);
    if (stats.pongs_recv == 0) {
        link_refuse(reply, "LINK_NO_PONG",
                    "no pong came back, so there is no latency to report",
                    "probe");
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

static void link_run_remote(const struct link_plan *plan,
                            struct zcl_command_reply *reply)
{
    uint8_t material[GAMELINK_MATERIAL_BYTES];
    if (!link_material(plan->key_hex, material)) {
        link_refuse(reply, "LINK_KEY_MALFORMED",
                    "key is exactly 64 hex characters", "input.key");
        return;
    }
    bool probing = strcmp(plan->mode, "probe") == 0;
    struct gamelink link = {.socket = -1};
    enum gamelink_status status =
        gamelink_open(&link, material, sizeof material, probing, plan->bind,
                      probing ? plan->peer : NULL, NULL);
    memset(material, 0, sizeof material);
    if (status != GAMELINK_OK) {
        link_refuse(reply, "LINK_OPEN_FAILED", gamelink_status_label(status),
                    probing ? "peer" : "bind");
        return;
    }
    if (probing)
        link_probe_loop(&link, NULL, plan->seconds);
    else
        link_echo_loop(&link, plan->seconds);
    struct gamelink_stats stats;
    gamelink_stats(&link, &stats);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet_link_probe.v1");
    (void)json_push_kv_str(&reply->data, "mode", plan->mode);
    (void)json_push_kv_int(&reply->data, "local_port", (int64_t)link.local_port);
    link_push_stats(&reply->data, &stats);
    gamelink_close(&link);
    /* An echo endpoint has no round trip of its own to report; it passes when
     * it served its window. A probe that heard nothing back FAILS: the point
     * of the leaf is the number, and printing zeros as if they were a
     * measurement is how an unreachable peer reads as a fast one. */
    if (probing && stats.pongs_recv == 0) {
        link_refuse(reply, "LINK_NO_PONG",
                    "no pong came back, so there is no latency to report",
                    "peer");
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

void zcl_native_handle_fleet_link_probe(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_link_probe.v1");
    struct link_plan plan;
    if (!link_read_plan(request, &plan, reply))
        return;
    if (strcmp(plan.mode, "loopback") == 0)
        link_run_loopback(&plan, reply);
    else
        link_run_remote(&plan, reply);
}
