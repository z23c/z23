/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood transport identity. */
#ifndef ZCL_RESEARCH_TRANSPORT_H
#define ZCL_RESEARCH_TRANSPORT_H

#include "base/result.h"

#include <stddef.h>

/* Copies the research message-start bytes, RPC port, and data-directory
 * name. Does not select the chain, open a socket, or write a store.
 * magic_cap and datadir_cap are byte counts. On failure the outputs are
 * left untouched. */
struct zcl_result research_transport_read(unsigned char *magic, size_t magic_cap,
                                         int *rpc_port, char *datadir,
                                         size_t datadir_cap);

#endif
