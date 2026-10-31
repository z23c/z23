/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_DEVICE_KEY_H
#define ZAPP_DEVICE_KEY_H
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Binds a 32 byte wallet secret to an AES-256-GCM key held in AndroidKeyStore. The key is generated
 * with setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL): Keystore
 * refuses every operation, encrypt and decrypt alike, that is not bound to one fresh authentication
 * by the owner's strong biometric or device credential. There is no validity window, so a retry, a
 * resume after Back and a second call each need their own prompt. The blob in app-private storage is
 * useless without that key.
 *
 * One call does the whole job: zapp_devkey_unwrap and zapp_devkey_wrap_new show a system
 * BiometricPrompt over a CryptoObject that holds the initialised Cipher, wait for the owner, and
 * return the secret or a typed refusal. They block until the owner answers, so call them from a
 * worker thread that is attached to the JVM, never from the UI thread. The prompt text is fixed by
 * the purpose and never carries an amount, an address or any other caller data. The minimum Android
 * level is 35 (the manifest), well above the 30 this key and prompt combination needs; the backend
 * refuses to create a key on an older release instead of weakening it.
 *
 * Call sites: wallet create calls zapp_devkey_wrap_new once (purpose "Protect this wallet"). Wallet
 * unlock calls zapp_devkey_unwrap with ZAPP_DEVKEY_PURPOSE_UNLOCK. A send calls zapp_devkey_unwrap
 * with ZAPP_DEVKEY_PURPOSE_PAYMENT once per payment and spends only on ZAPP_DEVKEY_OK. DECLINED is
 * the owner's choice (Back, cancel, a cancelled system prompt, the activity being destroyed) and is
 * not an error to retry silently.
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
    ZAPP_DEVKEY_DECLINED,         /* The owner did not authenticate: Back, cancel, dismissed, activity destroyed. */
    ZAPP_DEVKEY_INVALIDATED,      /* The key is gone for good: only the recovery phrase restores the wallet. */
    ZAPP_DEVKEY_NO_SCREEN_LOCK,   /* No secure lock screen: refuse to create or open a wallet. */
    ZAPP_DEVKEY_NOT_HARDWARE,     /* The key would live in software: refused. */
    ZAPP_DEVKEY_NOT_PER_USE,      /* The key does not require authentication for every use: refused. */
    ZAPP_DEVKEY_NOT_FOUND,        /* No key, or no blob, to open. */
    ZAPP_DEVKEY_EXISTS,           /* A wrapped secret is already stored: never overwritten. */
    ZAPP_DEVKEY_CORRUPT,          /* The blob is malformed or fails authentication. */
    ZAPP_DEVKEY_OLD_FORMAT,       /* A blob from the 30 second window design: refused, never opened. */
    ZAPP_DEVKEY_STRONGBOX_UNAVAILABLE,
    ZAPP_DEVKEY_ERROR
};
/* What the owner is told is being authorised; the backend maps each to a fixed sentence. */
enum zapp_devkey_purpose {
    ZAPP_DEVKEY_PURPOSE_CREATE,   /* "Protect this wallet" (wrap_new). */
    ZAPP_DEVKEY_PURPOSE_UNLOCK,   /* "Unlock this wallet". */
    ZAPP_DEVKEY_PURPOSE_PAYMENT   /* "Authorise this payment". */
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
 * AndroidKeyStore and BiometricPrompt, and tests implement it with a fake. seal and open each cost
 * the owner exactly one prompt and never reuse an earlier authentication. */
struct zapp_devkey_ops {
    void *ctx;
    bool (*random)(void *ctx, uint8_t *out, size_t len);
    enum zapp_devkey_status (*device_secure)(void *ctx);
    enum zapp_devkey_status (*create_key)(void *ctx, bool strongbox);
    /* per_use is true when the stored key requires authentication for every operation. */
    enum zapp_devkey_status (*key_policy)(void *ctx, enum zapp_devkey_level *level, bool *per_use);
    enum zapp_devkey_status (*seal)(void *ctx, const uint8_t *plain, size_t len,
                                    uint8_t iv[ZAPP_DEVKEY_IV], uint8_t sealed[ZAPP_DEVKEY_SEALED]);
    enum zapp_devkey_status (*open)(void *ctx, enum zapp_devkey_purpose purpose, const uint8_t iv[ZAPP_DEVKEY_IV],
                                    const uint8_t sealed[ZAPP_DEVKEY_SEALED], uint8_t *plain, size_t cap);
    void (*delete_key)(void *ctx);
};

/* Kinds of Java exception in a failure chain, as the JNI backend finds them with IsInstanceOf.
 * One bit mask per link, outermost first. */
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
 * missing or unreadable entry, and nothing else distinguishes it. A UserNotAuthenticatedException
 * cannot happen for a per-use key and is an error like every unrecognised chain. */
enum zapp_devkey_status zapp_devkey_classify_chain(const unsigned kinds[], size_t depth);

/* Refuses without a secure lock screen, creates the key when absent (StrongBox first, then secure
 * hardware) and reports where it lives. A key found in the keystore is never deleted; a key this
 * call created that is not hardware backed or not per-use is deleted and refused. With a blob path,
 * a blob that exists while the key is gone reports INVALIDATED instead of creating a replacement key. */
enum zapp_devkey_status zapp_devkey_prepare(const struct zapp_devkey_ops *ops, const char *path,
                                            struct zapp_devkey_info *info);
/* Draws 32 random bytes into secret, wraps them into the blob at path (0600, atomic, fsynced, never
 * over an existing blob) with one prompt. secret is zero unless the result is OK. */
enum zapp_devkey_status zapp_devkey_wrap_new(const struct zapp_devkey_ops *ops, const char *path,
                                             uint8_t secret[ZAPP_DEVKEY_SECRET]);
/* Reads the blob and unwraps it into secret with one prompt, which is zero unless the result is OK.
 * Only the unlock and payment purposes open a blob; any other purpose is an ERROR before any prompt.
 * Before the prompt it reads the stored key's policy itself and refuses a key that is not hardware
 * backed or does not authenticate every use, so it does not rely on an earlier prepare. Without a secure
 * lock screen it refuses before any prompt. A blob from an earlier format is OLD_FORMAT and never opened. */
enum zapp_devkey_status zapp_devkey_unwrap(const struct zapp_devkey_ops *ops, const char *path,
                                           enum zapp_devkey_purpose purpose,
                                           uint8_t secret[ZAPP_DEVKEY_SECRET]);
/* Removes the blob and the key. */
void zapp_devkey_discard(const struct zapp_devkey_ops *ops, const char *path);
const char *zapp_devkey_status_name(enum zapp_devkey_status status);
const char *zapp_devkey_level_name(enum zapp_devkey_level level);

/* One pending prompt, shared by the thread that waits and the threads that answer. It carries a
 * result code only, never key material. A ticket names one prompt: an answer for any other ticket
 * (a cancelled earlier prompt answering late) is ignored, and the first answer wins. */
enum zapp_devkey_answer {
    ZAPP_DEVKEY_ANSWER_NONE,
    ZAPP_DEVKEY_ANSWER_SUCCEEDED,
    ZAPP_DEVKEY_ANSWER_DECLINED,
    ZAPP_DEVKEY_ANSWER_NO_LOCK,
    ZAPP_DEVKEY_ANSWER_FAILED,
    ZAPP_DEVKEY_ANSWER_ABANDONED,  /* The activity was destroyed. */
    ZAPP_DEVKEY_ANSWER_TIMED_OUT
};
struct zapp_devkey_wait {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    unsigned long next, ticket;    /* ticket is zero when no prompt is pending. */
    enum zapp_devkey_answer answer;
};
#define ZAPP_DEVKEY_WAIT_INIT {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0, ZAPP_DEVKEY_ANSWER_NONE}
/* Opens a prompt and returns its ticket, or zero while another prompt is still pending. */
unsigned long zapp_devkey_wait_begin(struct zapp_devkey_wait *wait);
/* Records the answer of the prompt named by ticket; false when it is stale or already answered. */
bool zapp_devkey_wait_answer(struct zapp_devkey_wait *wait, unsigned long ticket, enum zapp_devkey_answer answer);
/* Blocks until the prompt is answered or timeout_ms passes, then retires the ticket. */
enum zapp_devkey_answer zapp_devkey_wait_end(struct zapp_devkey_wait *wait, unsigned long ticket, unsigned timeout_ms);
/* Answers whatever prompt is pending with ABANDONED; true when one was pending. */
bool zapp_devkey_wait_abandon(struct zapp_devkey_wait *wait);
/* BiometricPrompt error codes to answers: Back and cancel are DECLINED, a missing credential is
 * NO_LOCK, everything else FAILED. */
enum zapp_devkey_answer zapp_devkey_answer_for_error(int biometric_error);
enum zapp_devkey_status zapp_devkey_status_for_answer(enum zapp_devkey_answer answer);

#ifdef __ANDROID__
#include <jni.h>
struct zapp_devkey_jni {
    JNIEnv *env;
    jobject activity;
};
/* Fills ops with the AndroidKeyStore backend bound to state; both must outlive the calls, and env
 * must belong to the calling worker thread. */
void zapp_devkey_jni_ops(struct zapp_devkey_ops *ops, struct zapp_devkey_jni *state);
/* Ends a pending prompt with DECLINED and dismisses it; call from the activity's onDestroy. The
 * waiting thread returns at once and nothing stays referenced. */
void zapp_devkey_jni_abandon(JNIEnv *env);
#ifdef ZAPP_DEVKEY_PROBE
/* Outcome of an operation attempted without the authentication Keystore requires. */
struct zapp_devkey_misuse {
    bool accepted;                   /* Keystore ran the operation: the key is not enforcing per-use authentication. */
    bool control_ok;                 /* other_cipher only: the cipher the owner authenticated finished normally. */
    enum zapp_devkey_status refusal; /* How Keystore refused the unauthenticated operation. */
};
/* Probe only. Encrypts zeros with the stored key on a cipher that no prompt covers. With other_cipher
 * false the cipher is initialised and used with no prompt at all; with it true, one prompt
 * authenticates a first cipher and the operation runs on a second one that was initialised too. The
 * result is OK when the attempt was made, whatever Keystore answered. */
enum zapp_devkey_status zapp_devkey_jni_misuse(struct zapp_devkey_jni *state, bool other_cipher, struct zapp_devkey_misuse *result);
#endif
#endif
#endif
