/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_TX_SCRIPT_FACTS_H
#define ZCL_TX_SCRIPT_FACTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "ZCL script review requires ISO C23"
#endif

typedef struct {
    uint32_t p2sh_outputs;
    uint32_t op_return_outputs;
    bool zslp_marker;
} zcl_tx_script_facts;

/* Host-only wire observations. The marker does not validate a ZSLP transfer;
 * P2SH does not establish a multisig threshold. */
int zcl_tx_script_facts_parse(const uint8_t *wire, size_t length,
                              zcl_tx_script_facts *facts);

#endif
