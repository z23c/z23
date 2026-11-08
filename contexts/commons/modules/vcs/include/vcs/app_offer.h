/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Define canonical app offers and their plan bindings. */
#ifndef VCS_APP_OFFER_H
#define VCS_APP_OFFER_H

#include "vcs/package_release.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_APP_OFFER_SCHEMA "zcl.app_offer.v1"
#define ZCL_APP_OFFER_TEXT_MAX 2048u
#define ZCL_APP_OFFER_SIZE_MAX (5u * 1024u * 1024u)
#define ZCL_APP_OFFER_ONION_MAX 72u

struct zcl_app_offer {
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char root[65], publisher[67], carrier[65], sha256[65];
    int64_t size;
    char onion[ZCL_APP_OFFER_ONION_MAX + 1u];
};

bool vcs_app_offer_hex_valid(const char *s, size_t bytes);
bool vcs_app_offer_peer_is_onion(const char *peer);
/* Deterministic owner-plan binding; this identifies fields, not a human. */
void vcs_app_plan_hash(const char *domain, const char *const *parts,
                       size_t count, uint8_t out[32]);
bool vcs_app_get_recurring_plan(const struct zcl_app_offer *offer,
                                const char *post_id, const char *post_host,
                                const char *receive_plan, const char *datadir,
                                const char *token, uint8_t out[32]);
struct json_value;
bool vcs_app_offer_endpoint(const struct json_value *status, char host[static 63],
                            char endpoint[static ZCL_APP_OFFER_ONION_MAX + 1u]);
bool zcl_app_offer_valid(const struct zcl_app_offer *offer);
bool zcl_app_offer_format(const struct zcl_app_offer *offer, char *out, size_t cap);
bool zcl_app_offer_parse(const char *text, size_t len, struct zcl_app_offer *offer);
#endif
