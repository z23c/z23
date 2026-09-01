/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Thin lib/ wrapper. Pure amount/script compression now lives in
 * domain/consensus/coins_math.{c,h}; the wrappers here preserve the
 * exact legacy signatures so the on-disk coin/undo serializers and
 * existing callers don't need to change. */

#include "coins/compressor.h"

#include "domain/consensus/coins_math.h"

bool script_compress(const struct script *s, unsigned char *out, size_t *out_len)
{
    return coins_math_script_compress(s, out, out_len);
}

bool script_decompress(struct script *s, unsigned int nSize,
                       const unsigned char *in, size_t in_len)
{
    return coins_math_script_decompress(s, nSize, in, in_len);
}

unsigned int script_compress_special_size(unsigned int nSize)
{
    return coins_math_script_compress_special_size(nSize);
}

uint64_t compress_amount(uint64_t n)
{
    return coins_math_compress_amount(n);
}

uint64_t decompress_amount(uint64_t x)
{
    return coins_math_decompress_amount(x);
}
