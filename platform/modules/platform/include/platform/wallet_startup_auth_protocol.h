/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: define the private startup wallet authentication frame. */
#ifndef Z23_WALLET_STARTUP_AUTH_PROTOCOL_H
#define Z23_WALLET_STARTUP_AUTH_PROTOCOL_H

/* Eight-byte frame: magic ZWA1, type, zero reserved byte, uint16 LE length. */
#define Z23_WALLET_AUTH_HEADER_SIZE 8
#define Z23_WALLET_AUTH_REQUEST 1
#define Z23_WALLET_AUTH_SECRET 2
#define Z23_WALLET_AUTH_CANCEL 3
#define Z23_WALLET_AUTH_SECRET_MAX 512

#endif
