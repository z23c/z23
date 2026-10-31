/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_DEVICE_KEY_H
#define ZAPP_DEVICE_KEY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Binds a 32 byte wallet secret to an AES-256-GCM key held in AndroidKeyStore. The key requires a
 * device credential or strong biometric within the last 30 seconds, so every wrap and unwrap can
 * answer "needs authentication". The blob in app-private storage is useless without that key.
 *
 * Caller pattern for ZAPP_DEVKEY_NEEDS_AUTH: start zapp_devkey_confirm_credential once, return to the
 * event loop, and retry on the next resume. A retry that succeeds proves authentication, so no
 * activity result is read. A retry that is still NEEDS_AUTH means the owner declined: stop.
 *
 * Buffers: every buffer this module owns is cleansed on every exit path and the caller's secret is
 * zero on any result but OK. It cannot cleanse copies made outside this process or by the Java
 * runtime: the keystore service and binder transaction buffers, the Cipher provider's internal
 * state, and earlier copies of a Java byte[] left by a moving garbage collector. The JNI backend
 * zeroes every Java byte[] it creates or receives before dropping it, which covers the last copy. */
#define ZAPP_DEVKEY_SECRET 32u
#define ZAPP_DEVKEY_IV 12u
#define ZAPP_DEVKEY_SEALED 48u

enum zapp_devkey_status {
    ZAPP_DEVKEY_OK,
    ZAPP_DEVKEY_NEEDS_AUTH,       /* Authenticate, then retry. */
    ZAPP_DEVKEY_INVALIDATED,      /* The key is gone for good: only the recovery phrase restores the wallet. */
    ZAPP_DEVKEY_NO_SCREEN_LOCK,   /* No secure lock screen: refuse to create a wallet. */
    ZAPP_DEVKEY_NOT_HARDWARE,     /* The key would live in software: refused. */
    ZAPP_DEVKEY_NOT_FOUND,        /* No key, or no blob, to open. */
    ZAPP_DEVKEY_EXISTS,           /* A wrapped secret is already stored: never overwritten. */
    ZAPP_DEVKEY_CORRUPT,          /* The blob is malformed or fails authentication. */
    ZAPP_DEVKEY_STRONGBOX_UNAVAILABLE,
    ZAPP_DEVKEY_ERROR
};
enum zapp_devkey_level {
    ZAPP_DEVKEY_LEVEL_UNKNOWN,
    ZAPP_DEVKEY_LEVEL_SOFTWARE,
    ZAPP_DEVKEY_LEVEL_SECURE_HARDWARE,
    ZAPP_DEVKEY_LEVEL_STRONGBOX
};
struct zapp_devkey_info {
    enum zapp_devkey_level level;
    bool strongbox_fallback;      /* StrongBox was requested for a new key and was not available. */
};
/* The keystore seam. Each call reports one typed status; the JNI backend implements it with
 * AndroidKeyStore and tests implement it with a fake. */
struct zapp_devkey_ops {
    void *ctx;
    bool (*random)(void *ctx, uint8_t *out, size_t len);
    enum zapp_devkey_status (*device_secure)(void *ctx);
    enum zapp_devkey_status (*create_key)(void *ctx, bool strongbox);
    enum zapp_devkey_status (*key_level)(void *ctx, enum zapp_devkey_level *level);
    enum zapp_devkey_status (*seal)(void *ctx, const uint8_t *plain, size_t len,
                                    uint8_t iv[ZAPP_DEVKEY_IV], uint8_t sealed[ZAPP_DEVKEY_SEALED]);
    enum zapp_devkey_status (*open)(void *ctx, const uint8_t iv[ZAPP_DEVKEY_IV],
                                    const uint8_t sealed[ZAPP_DEVKEY_SEALED], uint8_t *plain, size_t cap);
    void (*delete_key)(void *ctx);
};

/* Kinds of Java exception in a failure chain, as the JNI backend finds them with IsInstanceOf.
 * One bit mask per link, outermost first. */
#define ZAPP_DEVKEY_EX_NOT_AUTHENTICATED 1u
#define ZAPP_DEVKEY_EX_PERMANENTLY_INVALIDATED 2u
#define ZAPP_DEVKEY_EX_UNRECOVERABLE_KEY 4u
#define ZAPP_DEVKEY_EX_BAD_TAG 8u
#define ZAPP_DEVKEY_EX_STRONGBOX_UNAVAILABLE 16u
#define ZAPP_DEVKEY_EX_UNKNOWN_ALGORITHM 32u    /* An UnrecoverableKeyException whose message is "Key algorithm unknown". */
/* Maps an exception chain to a status. INVALIDATED needs KeyPermanentlyInvalidatedException or an
 * UnrecoverableKeyException that carries no cause: the keystore wraps most other failures with a
 * cause, and a transient error must never report the key as gone. The causeless "Key algorithm
 * unknown" form is told apart by its message and is an error. Any other causeless
 * UnrecoverableKeyException still reads as invalidated: it is the form the keystore uses for a
 * missing or unreadable entry, and nothing else distinguishes it. Unrecognised chains are ERROR. */
enum zapp_devkey_status zapp_devkey_classify_chain(const unsigned kinds[], size_t depth);

/* Refuses without a secure lock screen, creates the key when absent (StrongBox first, then secure
 * hardware) and reports where it lives. A key found in the keystore is never deleted; a key this
 * call created that is not hardware backed is deleted and refused. With a blob path, a blob that
 * exists while the key is gone reports INVALIDATED instead of creating a replacement key. */
enum zapp_devkey_status zapp_devkey_prepare(const struct zapp_devkey_ops *ops, const char *path,
                                            struct zapp_devkey_info *info);
/* Draws 32 random bytes into secret, wraps them into the blob at path (0600, atomic, fsynced, never
 * over an existing blob). secret is zero unless the result is OK. */
enum zapp_devkey_status zapp_devkey_wrap_new(const struct zapp_devkey_ops *ops, const char *path,
                                             uint8_t secret[ZAPP_DEVKEY_SECRET]);
/* Reads the blob and unwraps it into secret, which is zero unless the result is OK. */
enum zapp_devkey_status zapp_devkey_unwrap(const struct zapp_devkey_ops *ops, const char *path,
                                           uint8_t secret[ZAPP_DEVKEY_SECRET]);
/* Removes the blob and the key. */
void zapp_devkey_discard(const struct zapp_devkey_ops *ops, const char *path);
const char *zapp_devkey_status_name(enum zapp_devkey_status status);
const char *zapp_devkey_level_name(enum zapp_devkey_level level);

#ifdef __ANDROID__
#include <jni.h>
struct zapp_devkey_jni {
    JNIEnv *env;
    jobject activity;
};
/* Fills ops with the AndroidKeyStore backend bound to state; both must outlive the calls. */
void zapp_devkey_jni_ops(struct zapp_devkey_ops *ops, struct zapp_devkey_jni *state);
/* Starts KeyguardManager.createConfirmDeviceCredentialIntent with plain startActivity. */
bool zapp_devkey_confirm_credential(JNIEnv *env, jobject activity);
#endif
#endif
