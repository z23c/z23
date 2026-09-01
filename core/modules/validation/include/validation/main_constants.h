/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_VALIDATION_MAIN_CONSTANTS_H
#define ZCL_VALIDATION_MAIN_CONSTANTS_H

#include <stdint.h>

/* CONSENSUS block-size reject limit: a node rejects any block whose
 * serialized size exceeds this. Matches zclassicd's GENEROUS_BLOCK_SIZE_LIMIT
 * (zclassic-cpp/src/main.cpp:3984, "2MB to accommodate any historical forks"),
 * NOT zclassicd's vestigial consensus.h MAX_BLOCK_SIZE=200000. Do NOT lower
 * this to 200000 — that would reject 200KB..2MB blocks zclassicd accepts. */
#define MAX_BLOCK_SIZE 2000000

/* MINING (block-production) cap — policy, NOT consensus. zclassicd's miner
 * caps the blocks it BUILDS at DEFAULT_BLOCK_MAX_SIZE = its (200KB)
 * MAX_BLOCK_SIZE (zclassic-cpp/src/main.h:53, miner.cpp:130-132), well below
 * the 2MB consensus reject limit. Mirror that 200000 so c23 produces blocks
 * the same size zclassicd does. A larger c23-mined block would still be
 * consensus-valid (≤2MB), so this is parity/policy, not a fork gate. */
#define DEFAULT_BLOCK_MAX_SIZE 200000
#define DEFAULT_BLOCK_MIN_SIZE 0
#define DEFAULT_BLOCK_PRIORITY_SIZE (DEFAULT_BLOCK_MAX_SIZE / 2)

#define DEFAULT_ALERTS true
#define ALERT_PRIORITY_SAFE_MODE 4000

#define COINBASE_MATURITY 100
#define ZCL_FINALITY_DEPTH 10
#define MAX_REORG_LENGTH ZCL_FINALITY_DEPTH
#define MAX_IBD_REORG_LENGTH 1000

#define MAX_P2SH_SIGOPS 15
#define MAX_BLOCK_SIGOPS 20000
#define MAX_STANDARD_TX_SIGOPS (MAX_BLOCK_SIGOPS / 5)
#define DEFAULT_MIN_RELAY_TX_FEE 100

#define DEFAULT_MAX_ORPHAN_TRANSACTIONS 100

#define DEFAULT_PRE_BUTTERCUP_TX_EXPIRY_DELTA 20
#define DEFAULT_POST_BUTTERCUP_TX_EXPIRY_DELTA \
    (DEFAULT_PRE_BUTTERCUP_TX_EXPIRY_DELTA * 4)

#define TX_EXPIRING_SOON_THRESHOLD 3

#define MAX_BLOCKFILE_SIZE 0x8000000
#define BLOCKFILE_CHUNK_SIZE 0x1000000
#define UNDOFILE_CHUNK_SIZE 0x100000

#define MAX_SCRIPTCHECK_THREADS 16
#define DEFAULT_SCRIPTCHECK_THREADS 0

#define MAX_BLOCKS_IN_TRANSIT_PER_PEER 128
#define BLOCK_STALLING_TIMEOUT 2
#define MAX_HEADERS_RESULTS 160
#define BLOCK_DOWNLOAD_WINDOW 4096

#define DATABASE_WRITE_INTERVAL (60 * 60)
#define DATABASE_FLUSH_INTERVAL (24 * 60 * 60)
#define MAX_REJECT_MESSAGE_LENGTH 111
#define DEFAULT_MAX_TIP_AGE (24 * 60 * 60)

#define DEFAULT_MAX_REORG_DEPTH ZCL_FINALITY_DEPTH
#define DEFAULT_PRE_BUTTERCUP_MIN_FINALIZATION_DELAY (30 * 60)
#define DEFAULT_POST_BUTTERCUP_MIN_FINALIZATION_DELAY \
    (DEFAULT_PRE_BUTTERCUP_MIN_FINALIZATION_DELAY / 2)

#define MIN_DISK_SPACE ((uint64_t)52428800)
#define MIN_BLOCKS_TO_KEEP 288
#define MIN_DISK_SPACE_FOR_BLOCK_FILES ((uint64_t)(550 * 1024 * 1024))

#define REJECT_INTERNAL 0x100
#define REJECT_AGAINST_FINALIZED 0x103

#endif
