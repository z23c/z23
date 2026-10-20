/* purpose: Share the fleet pairing-epoch reader, smoke gate and path rules between the pair.status and pair.renew leaves. */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_TOOLS_NATIVE_PAIR_COMMON_H
#define ZCL_TOOLS_NATIVE_PAIR_COMMON_H

#include "command/native_command.h"
#include "models/device_pairing.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PAIR_PATH_MAX 1100
#define PAIR_NAME_MAX 17
#define PAIR_EPOCH_LIST_MAX 64
/* Documented renewal threshold: a pairing is renew_due when it expires within 72 h. */
#define PAIR_RENEW_BEFORE_DEFAULT_S UINT64_C(259200)
#define PAIR_RENEW_BEFORE_MIN_S UINT64_C(3600)
#define PAIR_RENEW_BEFORE_MAX_S UINT64_C(2592000)

enum pair_state { PAIR_ACTIVE, PAIR_EXPIRED, PAIR_REVOKED };

/* One client-side epoch directory <state>/<peer>-e<N>: the route file plus the
 * grant its profile holds for the hub. Public facts only; the PSK is never held. */
struct pair_epoch {
    uint32_t epoch;
    char client[PAIR_NAME_MAX], route_id[64], route_address[16];
    char dir[PAIR_PATH_MAX], profile[PAIR_PATH_MAX];
    uint8_t peer_key[32], cfg_root[32], root[32];
    uint16_t target_port, route_port;
    struct db_device_pairing row;
    char credential[65], psk_fp[17];
};

bool pair_name_ok(const char *text);
bool pair_path_ok(const char *text);
uint64_t pair_now(void);
/* Highest N among entries named <prefix>-e<N> directly inside dir (0 when none). */
uint32_t pair_dir_max(const char *dir, const char *prefix);
/* Epochs holding a client.json, ascending. */
size_t pair_epoch_list(const char *state, const char *peer, uint32_t *epochs, size_t cap);
bool pair_epoch_load(const char *state, const char *peer, uint32_t epoch, struct pair_epoch *out);
enum pair_state pair_epoch_state(const struct pair_epoch *epoch, uint64_t now);
const char *pair_state_name(enum pair_state state);
bool pair_renew_due(const struct pair_epoch *epoch, uint64_t now, uint64_t before_s);
/* Fingerprint (first 16 hex of the domain-separated SHA3-256) of the PSK a profile holds
 * for peer under root; false when the grant cannot be acquired (expired, revoked). */
bool pair_psk_fingerprint(const char *profile, const uint8_t peer[32], const uint8_t root[32],
                          uint16_t port, enum device_pairing_host_direction direction,
                          uint64_t now, char out[17]);
bool pair_epoch_emit(struct json_value *object, const struct pair_epoch *epoch, uint64_t now,
                     uint64_t before_s, bool current);

struct pair_smoke_in {
    const char *client_profile, *hub_profile;
    uint8_t client_key[32], hub_key[32], client_root[32], hub_root[32];
    uint16_t target_port;
    uint32_t budget_ms;
    bool corrupt; /* test-only: client approves a wrong hub root */
};
struct pair_smoke_out {
    bool passed;
    char reason[32];
    uint16_t listen_port;
    uint32_t accepted;
};
/* Run the real receiver and client PSK runtimes against the hub and client
 * grants on loopback and require the target's first bytes (the "SSH-" banner)
 * to arrive through the tunnel. Mutates nothing. */
void pair_smoke_run(const struct pair_smoke_in *in, struct pair_smoke_out *out);
#endif
