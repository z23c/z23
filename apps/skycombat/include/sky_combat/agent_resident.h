/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
#ifndef SKY_COMBAT_AGENT_RESIDENT_H
#define SKY_COMBAT_AGENT_RESIDENT_H

#include "platform/resident_launch.h"

/* Child transport only. The parent owns launch/image acceptance and deadlines. */
struct sky_resident_channel {
    bool active;
    char nonce[RESIDENT_LAUNCH_NONCE_HEX + 1u];
};

bool sky_resident_nonce_valid(const char *nonce);
bool sky_game_raise_open(void);
bool sky_game_raise_close(void);
void sky_game_raise_apply(void);
void sky_game_event_pump(void);
bool sky_resident_open(struct sky_resident_channel *channel, const char *nonce);
bool sky_resident_close(struct sky_resident_channel *channel);
int sky_resident_read(struct sky_resident_channel *channel, char *payload,
                       size_t *length);
bool sky_resident_write(struct sky_resident_channel *channel,
                         const char *payload, size_t length);

#endif
