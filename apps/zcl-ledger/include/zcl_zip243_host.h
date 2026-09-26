/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_ZIP243_HOST_H
#define ZCL_ZIP243_HOST_H

#include "zcl_zip243.h"
#include "crypto/blake2b.h"

zcl_zip243_hasher zcl_zip243_host_hasher(struct blake2b_ctx *context);

#endif
