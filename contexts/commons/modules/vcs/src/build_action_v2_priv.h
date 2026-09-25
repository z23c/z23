/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Rule set shared by the action preimage v2 encoder and decoder. */

#ifndef ZCL_VCS_BUILD_ACTION_V2_PRIV_H
#define ZCL_VCS_BUILD_ACTION_V2_PRIV_H

#include "vcs/build_action.h"

#include <stdbool.h>
#include <stddef.h>

#define AV2_MAGIC_LEN (sizeof(VCS_ACTION_PREIMAGE_V2_MAGIC))

void vcs_action_v2_set_why(char *why, size_t why_len, const char *what,
                           const char *detail);
/* The single semantic validator: the encoder refuses what the decoder
 * would refuse, so every accepted byte string has exactly one spelling. */
bool vcs_action_preimage_v2_check(const struct vcs_action_preimage_v2 *in,
                                  char *why, size_t why_len);

#endif /* ZCL_VCS_BUILD_ACTION_V2_PRIV_H */
