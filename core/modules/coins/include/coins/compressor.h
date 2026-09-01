/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_COMPRESSOR_H
#define ZCL_COMPRESSOR_H

#include "keys/pubkey.h"
#include "script/script.h"
#include <stdbool.h>
#include <stdint.h>

bool script_compress(const struct script *s, unsigned char *out, size_t *out_len);
bool script_decompress(struct script *s, unsigned int nSize,
                       const unsigned char *in, size_t in_len);
unsigned int script_compress_special_size(unsigned int nSize);

uint64_t compress_amount(uint64_t n);
uint64_t decompress_amount(uint64_t x);

#endif
