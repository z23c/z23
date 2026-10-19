/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_TX_SHIELDED_REPLAY_H
#define ZCL_TX_SHIELDED_REPLAY_H

#include "zcl_tx_shielded_stream.h"
#include "zcl_zip243.h"
#include "zsha256/zsha256.h"

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "Shielded ZIP-243 replay requires ISO C23"
#endif

typedef struct {
    uint8_t cv[32], cm[32], epk[32];
    uint8_t enc_ciphertext[580], out_ciphertext[80];
} zcl_tx_shielded_output_capture;

typedef struct {
    zcl_tx_shielded_stream wire;
    zcl_tx_shielded_facts facts;
    zcl_zip243_hasher blake;
    zsha256_ctx sha;
    uint8_t commitment[32], parts[6][32], header[8], tail[16];
    uint8_t *spend_rk;
    zcl_tx_shielded_output_capture *output_capture;
    uint32_t expected, branch_id;
    uint32_t spend_index, output_index;
    uint8_t pass, header_used, tail_used, rk_used;
    uint16_t output_used;
    bool failed;
} zcl_tx_shielded_replay;

/* The host uploads the identical complete wire six times. Each pass derives
 * one ZIP-243 section hash from independently parsed bytes and checks its
 * full-wire SHA-256 against pass one. No partial or substituted pass returns
 * a digest. Branch selection and payment approval still need device-enforced
 * policy; this read-only digest grants no signing authority. */
bool zcl_tx_shielded_replay_begin(zcl_tx_shielded_replay *state,
    uint32_t expected_length, uint32_t branch_id,
    const zcl_zip243_hasher *blake);
/* Capture one indexed spend rk from the first parsed pass. The output is
 * provisional until finish succeeds after six identical complete passes.
 * A failed replay clears the caller's 32-byte rk. On success, the caller
 * owns and must erase the verified rk. Output must not overlap the replay
 * state or the hash context. Fixed-size buffer overlap and a hash context
 * starting inside one are rejected before writes; the caller must ensure the
 * entire hash context is disjoint and erase rejected buffers. */
bool zcl_tx_shielded_replay_begin_rk(zcl_tx_shielded_replay *state,
    uint32_t expected_length, uint32_t branch_id,
    const zcl_zip243_hasher *blake, uint32_t spend_index,
    uint8_t spend_rk[32]);
/* Capture the selected output's cv, cm, epk, and both ciphertexts from
 * pass one. The capture is provisional until all six full-wire commitments
 * match. Failure or abort clears it; after success the caller owns and must
 * erase it. No recipient or amount is established by capture alone;
 * decryption and note-commitment verification are needed.
 * The capture must not overlap replay state or the hash context. Fixed-size
 * buffer overlap and a hash context starting inside one are rejected before
 * writes; the caller must ensure the entire context is disjoint and erase
 * rejected buffers. */
bool zcl_tx_shielded_replay_begin_output(zcl_tx_shielded_replay *state,
    uint32_t expected_length, uint32_t branch_id,
    const zcl_zip243_hasher *blake, uint32_t output_index,
    zcl_tx_shielded_output_capture *output);
/* Bind one spend rk and one output capture to the same six-pass wire replay.
 * Neither result is authoritative until finish succeeds. Failure or abort
 * clears both captures; after success the caller owns and must erase them.
 * Both outputs must be distinct from each other, the replay state, and the
 * hash context. Fixed-size buffer overlap and a hash context starting inside
 * one are rejected before writes; the caller must ensure the entire context
 * is disjoint and erase rejected buffers. This is capture only, not payment
 * approval. */
bool zcl_tx_shielded_replay_begin_captures(zcl_tx_shielded_replay *state,
    uint32_t expected_length, uint32_t branch_id,
    const zcl_zip243_hasher *blake, uint32_t spend_index,
    uint8_t spend_rk[32], uint32_t output_index,
    zcl_tx_shielded_output_capture *output);
/* Feed bytes must not overlap replay state or provisional captures. An
 * overlap aborts and erases all three before parsing or hashing. */
bool zcl_tx_shielded_replay_feed(zcl_tx_shielded_replay *state,
    const uint8_t *bytes, size_t length);
bool zcl_tx_shielded_replay_next(zcl_tx_shielded_replay *state);
/* Facts and digest must be disjoint from each other, replay state, hash
 * context, and provisional captures. Fixed-size overlap and a context base
 * inside an output abort and erase the replay and captures. The caller must
 * ensure the entire hash context is disjoint. */
bool zcl_tx_shielded_replay_finish(zcl_tx_shielded_replay *state,
    zcl_tx_shielded_facts *facts, uint8_t digest[32]);
/* Erase an active replay and any provisional rk or output capture. Call
 * before abandoning an upload or reusing a state that began with capture. */
void zcl_tx_shielded_replay_abort(zcl_tx_shielded_replay *state);

#endif
