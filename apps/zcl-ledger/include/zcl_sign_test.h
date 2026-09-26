/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_SIGN_TEST_H
#define ZCL_SIGN_TEST_H

#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue signing self-test requires ISO C23"
#endif

#define ZCL_SIGN_TEST_MESSAGE "Z23 ZCL Blue signing self-test v1"
#define ZCL_SIGN_TEST_PATH "m/44'/147'/0'/0/0"

enum { ZCL_SIGN_TEST_PUBKEY_SIZE = 33, ZCL_SIGN_TEST_MAX_DER = 72 };

/* Validates the Blue response and its ECDSA signature over the fixed message. */
int zcl_sign_test_verify(const uint8_t *reply, size_t length,
                         uint8_t pubkey[ZCL_SIGN_TEST_PUBKEY_SIZE]);

#endif
