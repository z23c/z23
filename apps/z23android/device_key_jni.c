/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "device_key.h"
#include "base/cleanse.h"
#include "jni_util.h"
#include <stdarg.h>
#include <string.h>

#define ALIAS "z23.wallet.device-key.v1"
#define AAD "z23.wallet.device-key.v1"
#define AUTH_WINDOW_SECONDS 30
/* KeyProperties.PURPOSE_ENCRYPT | PURPOSE_DECRYPT, and AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL. */
#define PURPOSES 3
#define AUTH_TYPES 3
#define BUILDER_SIG(args) "(" args ")Landroid/security/keystore/KeyGenParameterSpec$Builder;"

typedef enum zapp_devkey_status status_t;

static bool frame_begin(JNIEnv *env)
{
    if ((*env)->PushLocalFrame(env, 48) == JNI_OK) return true;
    (void)zj_clean(env); return false;
}
static void frame_end(JNIEnv *env) { (void)zj_clean(env); (*env)->PopLocalFrame(env, NULL); }

/* Overwrites a Java byte[] with zeros; the garbage collector may have left earlier copies. */
static void bytes_wipe(JNIEnv *env, jbyteArray array)
{
    if (!array) return;
    jthrowable pending = (*env)->ExceptionOccurred(env);
    if (pending) (*env)->ExceptionClear(env);
    jsize length = (*env)->GetArrayLength(env, array);
    jbyte zeros[64] = {0};
    for (jsize at = 0; at < length && zj_clean(env); at += (jsize)sizeof(zeros)) {
        jsize part = length - at < (jsize)sizeof(zeros) ? length - at : (jsize)sizeof(zeros);
        (*env)->SetByteArrayRegion(env, array, at, part, zeros);
    }
    (void)zj_clean(env);
    if (pending) { (void)(*env)->Throw(env, pending); (*env)->DeleteLocalRef(env, pending); }
}
static jbyteArray bytes_new(JNIEnv *env, const uint8_t *data, size_t len)
{
    jbyteArray array = (*env)->NewByteArray(env, (jsize)len);
    if (array) (*env)->SetByteArrayRegion(env, array, 0, (jsize)len, (const jbyte *)data);
    return zj_clean(env) ? array : NULL;
}
/* Copies exactly len bytes out of a Java byte[], then wipes it. */
static bool bytes_take(JNIEnv *env, jbyteArray array, uint8_t *out, size_t len)
{
    bool ok = array && (size_t)(*env)->GetArrayLength(env, array) == len;
    if (ok) (*env)->GetByteArrayRegion(env, array, 0, (jsize)len, (jbyte *)out);
    ok = zj_clean(env) && ok;
    bytes_wipe(env, array);
    if (!ok) memory_cleanse(out, len);
    return ok;
}
static jobject string_array1(JNIEnv *env, const char *value)
{
    jclass string_cls = (*env)->FindClass(env, "java/lang/String");
    jstring text = zj_clean(env) ? (*env)->NewStringUTF(env, value) : NULL;
    jobjectArray array = text ? (*env)->NewObjectArray(env, 1, string_cls, text) : NULL;
    return zj_clean(env) ? array : NULL;
}

#define CHAIN_MAX 8
/* True when the exception message equals text. */
static bool message_is(JNIEnv *env, jthrowable thrown, const char *text)
{
    jobject message = zj_object_property(env, thrown, "getMessage", "()Ljava/lang/String;");
    const char *chars = message ? (*env)->GetStringUTFChars(env, message, NULL) : NULL;
    bool same = chars && !strcmp(chars, text);
    if (chars) (*env)->ReleaseStringUTFChars(env, message, chars);
    if (message) (*env)->DeleteLocalRef(env, message);
    (void)zj_clean(env);
    return same;
}
/* The ZAPP_DEVKEY_EX_ kinds of one exception in the chain. */
static unsigned link_kinds(JNIEnv *env, jthrowable thrown)
{
    static const struct { const char *name; unsigned kind; } known[] = {
        {"android/security/keystore/UserNotAuthenticatedException", ZAPP_DEVKEY_EX_NOT_AUTHENTICATED},
        {"android/security/keystore/KeyPermanentlyInvalidatedException", ZAPP_DEVKEY_EX_PERMANENTLY_INVALIDATED},
        {"java/security/UnrecoverableKeyException", ZAPP_DEVKEY_EX_UNRECOVERABLE_KEY},
        {"javax/crypto/AEADBadTagException", ZAPP_DEVKEY_EX_BAD_TAG},
        {"android/security/keystore/StrongBoxUnavailableException", ZAPP_DEVKEY_EX_STRONGBOX_UNAVAILABLE}};
    unsigned kinds = 0;
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); ++i) {
        jclass cls = (*env)->FindClass(env, known[i].name);
        if (zj_clean(env) && cls && (*env)->IsInstanceOf(env, thrown, cls)) kinds |= known[i].kind;
        if (cls) (*env)->DeleteLocalRef(env, cls);
    }
    if ((kinds & ZAPP_DEVKEY_EX_UNRECOVERABLE_KEY) && message_is(env, thrown, "Key algorithm unknown")) kinds |= ZAPP_DEVKEY_EX_UNKNOWN_ALGORITHM;
    return kinds;
}
/* Maps the pending Java exception to a status and clears it. The chain of causes is read to its end
 * (a longer chain is cut with an unknown link so it never looks causeless). */
static status_t classify(JNIEnv *env)
{
    jthrowable thrown = (*env)->ExceptionOccurred(env);
    if (!thrown) return ZAPP_DEVKEY_ERROR;
    (*env)->ExceptionClear(env);
    unsigned kinds[CHAIN_MAX + 1] = {0};
    size_t depth = 0;
    while (thrown && depth < CHAIN_MAX) {
        kinds[depth] = link_kinds(env, thrown);
        ++depth;
        jobject cause = zj_object_property(env, thrown, "getCause", "()Ljava/lang/Throwable;");
        (*env)->DeleteLocalRef(env, thrown);
        thrown = cause;
    }
    if (thrown) { (*env)->DeleteLocalRef(env, thrown); depth = CHAIN_MAX + 1; }
    return zapp_devkey_classify_chain(kinds, depth);
}
/* The status for a failed call: the classified exception, or ERROR when nothing was thrown. */
static status_t failed(JNIEnv *env) { return (*env)->ExceptionCheck(env) ? classify(env) : ZAPP_DEVKEY_ERROR; }

static jobject call_static(JNIEnv *env, jclass cls, const char *name, const char *sig, ...)
{
    jmethodID method = cls ? (*env)->GetStaticMethodID(env, cls, name, sig) : NULL;
    if (!zj_clean(env) || !method) return NULL;
    va_list args; va_start(args, sig);
    jobject result = (*env)->CallStaticObjectMethodV(env, cls, method, args);
    va_end(args);
    return result;
}
/* Instance call that leaves any exception pending for failed(). */
static jobject call_object(JNIEnv *env, jobject obj, const char *name, const char *sig, ...)
{
    jmethodID method = zj_method(env, obj, name, sig);
    if (!method) return NULL;
    va_list args; va_start(args, sig);
    jobject result = (*env)->CallObjectMethodV(env, obj, method, args);
    va_end(args);
    return result;
}
static bool call_void(JNIEnv *env, jobject obj, const char *name, const char *sig, ...)
{
    jmethodID method = zj_method(env, obj, name, sig);
    if (!method) return false;
    va_list args; va_start(args, sig);
    (*env)->CallVoidMethodV(env, obj, method, args);
    va_end(args);
    return !(*env)->ExceptionCheck(env);
}
static jobject new_object(JNIEnv *env, const char *type, const char *sig, ...)
{
    jclass cls = (*env)->FindClass(env, type);
    jmethodID ctor = zj_clean(env) && cls ? (*env)->GetMethodID(env, cls, "<init>", sig) : NULL;
    if (!zj_clean(env) || !ctor) return NULL;
    va_list args; va_start(args, sig);
    jobject result = (*env)->NewObjectV(env, cls, ctor, args);
    va_end(args);
    return result;
}

static status_t jni_device_secure(void *context)
{
    JNIEnv *env = ((struct zapp_devkey_jni *)context)->env;
    jobject activity = ((struct zapp_devkey_jni *)context)->activity;
    if (!frame_begin(env)) return ZAPP_DEVKEY_ERROR;
    jstring name = (*env)->NewStringUTF(env, "keyguard");
    jobject guard = name ? call_object(env, activity, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;", name) : NULL;
    jmethodID secure = zj_clean(env) && guard ? zj_method(env, guard, "isDeviceSecure", "()Z") : NULL;
    jboolean value = secure ? (*env)->CallBooleanMethod(env, guard, secure) : JNI_FALSE;
    status_t st = zj_clean(env) && secure ? (value ? ZAPP_DEVKEY_OK : ZAPP_DEVKEY_NO_SCREEN_LOCK) : ZAPP_DEVKEY_ERROR;
    frame_end(env);
    return st;
}

static bool builder_step(JNIEnv *env, jobject builder, const char *name, const char *sig, ...)
{
    jmethodID method = zj_method(env, builder, name, sig);
    if (!method) return false;
    va_list args; va_start(args, sig);
    jobject again = (*env)->CallObjectMethodV(env, builder, method, args);
    va_end(args);
    if (again) (*env)->DeleteLocalRef(env, again);
    return zj_clean(env);
}
static jobject key_spec(JNIEnv *env, bool strongbox)
{
    jstring alias = (*env)->NewStringUTF(env, ALIAS);
    jobject modes = string_array1(env, "GCM"), paddings = string_array1(env, "NoPadding");
    jobject builder = alias && modes && paddings ?
        new_object(env, "android/security/keystore/KeyGenParameterSpec$Builder", "(Ljava/lang/String;I)V", alias, PURPOSES) : NULL;
    bool ok = builder && builder_step(env, builder, "setBlockModes", BUILDER_SIG("[Ljava/lang/String;"), modes) &&
        builder_step(env, builder, "setEncryptionPaddings", BUILDER_SIG("[Ljava/lang/String;"), paddings) &&
        builder_step(env, builder, "setKeySize", BUILDER_SIG("I"), 256) &&
        builder_step(env, builder, "setUserAuthenticationRequired", BUILDER_SIG("Z"), JNI_TRUE) &&
        builder_step(env, builder, "setUserAuthenticationParameters", BUILDER_SIG("II"), AUTH_WINDOW_SECONDS, AUTH_TYPES) &&
        builder_step(env, builder, "setUnlockedDeviceRequired", BUILDER_SIG("Z"), JNI_TRUE) &&
        builder_step(env, builder, "setInvalidatedByBiometricEnrollment", BUILDER_SIG("Z"), JNI_FALSE) &&
        builder_step(env, builder, "setIsStrongBoxBacked", BUILDER_SIG("Z"), strongbox ? JNI_TRUE : JNI_FALSE);
    jobject spec = ok ? call_object(env, builder, "build", "()Landroid/security/keystore/KeyGenParameterSpec;") : NULL;
    return zj_clean(env) ? spec : NULL;
}
static status_t jni_create_key(void *context, bool strongbox)
{
    JNIEnv *env = ((struct zapp_devkey_jni *)context)->env;
    status_t st = ZAPP_DEVKEY_ERROR;
    if (!frame_begin(env)) return ZAPP_DEVKEY_ERROR;
    jclass generator = (*env)->FindClass(env, "javax/crypto/KeyGenerator");
    jstring algorithm = zj_clean(env) ? (*env)->NewStringUTF(env, "AES") : NULL;
    jstring provider = algorithm ? (*env)->NewStringUTF(env, "AndroidKeyStore") : NULL;
    jobject maker = provider ? call_static(env, generator, "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;", algorithm, provider) : NULL;
    jobject spec = zj_clean(env) && maker ? key_spec(env, strongbox) : NULL;
    jobject made = spec && call_void(env, maker, "init", "(Ljava/security/spec/AlgorithmParameterSpec;)V", spec) ?
        call_object(env, maker, "generateKey", "()Ljavax/crypto/SecretKey;") : NULL;
    if (made) st = ZAPP_DEVKEY_OK;
    else if (spec && strongbox && failed(env) == ZAPP_DEVKEY_STRONGBOX_UNAVAILABLE) st = ZAPP_DEVKEY_STRONGBOX_UNAVAILABLE;
    frame_end(env);
    return st;
}

/* The keystore entry, or NULL with *status set: NOT_FOUND when absent. */
static jobject stored_key(JNIEnv *env, status_t *status)
{
    jclass store = (*env)->FindClass(env, "java/security/KeyStore");
    jstring type = zj_clean(env) ? (*env)->NewStringUTF(env, "AndroidKeyStore") : NULL;
    jobject keystore = type ? call_static(env, store, "getInstance", "(Ljava/lang/String;)Ljava/security/KeyStore;", type) : NULL;
    bool loaded = keystore && call_void(env, keystore, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V", NULL);
    jstring alias = loaded ? (*env)->NewStringUTF(env, ALIAS) : NULL;
    jobject key = alias ? call_object(env, keystore, "getKey", "(Ljava/lang/String;[C)Ljava/security/Key;", alias, NULL) : NULL;
    if (key) return key;
    *status = (*env)->ExceptionCheck(env) ? failed(env) : (alias ? ZAPP_DEVKEY_NOT_FOUND : ZAPP_DEVKEY_ERROR);
    return NULL;
}
static enum zapp_devkey_level level_of(jint security_level)
{
    switch (security_level) {
    case 2: return ZAPP_DEVKEY_LEVEL_STRONGBOX;
    case 1: case -2: return ZAPP_DEVKEY_LEVEL_SECURE_HARDWARE;
    case 0: return ZAPP_DEVKEY_LEVEL_SOFTWARE;
    default: return ZAPP_DEVKEY_LEVEL_UNKNOWN;
    }
}
/* Reads the security level of the stored key from its KeyInfo. */
static bool key_info_level(JNIEnv *env, jobject key, enum zapp_devkey_level *level)
{
    jclass factory = (*env)->FindClass(env, "javax/crypto/SecretKeyFactory");
    jclass info_cls = zj_clean(env) && factory ? (*env)->FindClass(env, "android/security/keystore/KeyInfo") : NULL;
    jstring algorithm = zj_clean(env) && info_cls ? (*env)->NewStringUTF(env, "AES") : NULL;
    jstring provider = algorithm ? (*env)->NewStringUTF(env, "AndroidKeyStore") : NULL;
    jobject maker = provider ? call_static(env, factory, "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;", algorithm, provider) : NULL;
    jobject info = zj_clean(env) && maker ? call_object(env, maker, "getKeySpec",
        "(Ljavax/crypto/SecretKey;Ljava/lang/Class;)Ljava/security/spec/KeySpec;", key, info_cls) : NULL;
    jmethodID get = zj_clean(env) && info ? zj_method(env, info, "getSecurityLevel", "()I") : NULL;
    jint value = get ? (*env)->CallIntMethod(env, info, get) : 0;
    if (!get || !zj_clean(env)) return false;
    *level = level_of(value);
    return true;
}
static status_t jni_key_level(void *context, enum zapp_devkey_level *level)
{
    JNIEnv *env = ((struct zapp_devkey_jni *)context)->env;
    status_t st = ZAPP_DEVKEY_ERROR;
    if (!frame_begin(env)) return st;
    jobject key = stored_key(env, &st);
    if (key) st = key_info_level(env, key, level) ? ZAPP_DEVKEY_OK : ZAPP_DEVKEY_ERROR;
    frame_end(env);
    return st;
}

static jobject cipher_for(JNIEnv *env, int mode, jobject key, jobject parameters)
{
    jclass cipher_cls = (*env)->FindClass(env, "javax/crypto/Cipher");
    jstring transform = zj_clean(env) ? (*env)->NewStringUTF(env, "AES/GCM/NoPadding") : NULL;
    jobject cipher = transform ? call_static(env, cipher_cls, "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;", transform) : NULL;
    bool ready = cipher && (parameters ?
        call_void(env, cipher, "init", "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V", mode, key, parameters) :
        call_void(env, cipher, "init", "(ILjava/security/Key;)V", mode, key));
    return ready ? cipher : NULL;
}
/* Binds the blob to this wallet purpose, then runs the cipher over input. Returns the output. */
static jbyteArray cipher_run(JNIEnv *env, jobject cipher, jbyteArray input)
{
    jbyteArray aad = bytes_new(env, (const uint8_t *)AAD, strlen(AAD));
    bool bound = aad && call_void(env, cipher, "updateAAD", "([B)V", aad);
    bytes_wipe(env, aad);
    return bound ? call_object(env, cipher, "doFinal", "([B)[B", input) : NULL;
}
/* Copies the sealed bytes and the nonce out of Java, wiping both Java arrays. */
static bool seal_copy(JNIEnv *env, jobject cipher, jbyteArray output, uint8_t iv[ZAPP_DEVKEY_IV], uint8_t sealed[ZAPP_DEVKEY_SEALED])
{
    jbyteArray nonce = (jbyteArray)call_object(env, cipher, "getIV", "()[B");
    if (!zj_clean(env)) nonce = NULL;
    bool copied = bytes_take(env, output, sealed, ZAPP_DEVKEY_SEALED) && nonce && bytes_take(env, nonce, iv, ZAPP_DEVKEY_IV);
    if (!copied) { memory_cleanse(sealed, ZAPP_DEVKEY_SEALED); memory_cleanse(iv, ZAPP_DEVKEY_IV); }
    return copied;
}
static status_t jni_seal(void *context, const uint8_t *plain, size_t len, uint8_t iv[ZAPP_DEVKEY_IV], uint8_t sealed[ZAPP_DEVKEY_SEALED])
{
    JNIEnv *env = ((struct zapp_devkey_jni *)context)->env;
    status_t st = ZAPP_DEVKEY_ERROR;
    if (!frame_begin(env)) return st;
    jobject key = stored_key(env, &st);
    jobject cipher = key ? cipher_for(env, 1, key, NULL) : NULL;
    if (key && !cipher) st = failed(env);
    jbyteArray input = cipher ? bytes_new(env, plain, len) : NULL;
    jbyteArray output = input ? cipher_run(env, cipher, input) : NULL;
    if (input && !output) st = failed(env);
    bytes_wipe(env, input);
    if (output) st = seal_copy(env, cipher, output, iv, sealed) ? ZAPP_DEVKEY_OK : ZAPP_DEVKEY_ERROR;
    frame_end(env);
    return st;
}
static status_t jni_open(void *context, const uint8_t iv[ZAPP_DEVKEY_IV], const uint8_t sealed[ZAPP_DEVKEY_SEALED], uint8_t *plain, size_t cap)
{
    JNIEnv *env = ((struct zapp_devkey_jni *)context)->env;
    status_t st = ZAPP_DEVKEY_ERROR;
    if (!frame_begin(env)) return st;
    jobject key = stored_key(env, &st);
    jbyteArray nonce = key ? bytes_new(env, iv, ZAPP_DEVKEY_IV) : NULL;
    jobject params = nonce ? new_object(env, "javax/crypto/spec/GCMParameterSpec", "(I[B)V", 128, nonce) : NULL;
    bytes_wipe(env, nonce);
    jobject cipher = params ? cipher_for(env, 2, key, params) : NULL;
    if (params && !cipher) st = failed(env);
    jbyteArray input = cipher ? bytes_new(env, sealed, ZAPP_DEVKEY_SEALED) : NULL;
    jbyteArray output = input ? cipher_run(env, cipher, input) : NULL;
    if (input && !output) st = failed(env);
    bytes_wipe(env, input);
    if (output) st = bytes_take(env, output, plain, cap) ? ZAPP_DEVKEY_OK : ZAPP_DEVKEY_ERROR;
    frame_end(env);
    return st;
}
static void jni_delete_key(void *context)
{
    JNIEnv *env = ((struct zapp_devkey_jni *)context)->env;
    if (!frame_begin(env)) return;
    jclass store = (*env)->FindClass(env, "java/security/KeyStore");
    jstring type = zj_clean(env) ? (*env)->NewStringUTF(env, "AndroidKeyStore") : NULL;
    jobject keystore = type ? call_static(env, store, "getInstance", "(Ljava/lang/String;)Ljava/security/KeyStore;", type) : NULL;
    jstring alias = keystore && call_void(env, keystore, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V", NULL) ?
        (*env)->NewStringUTF(env, ALIAS) : NULL;
    if (alias) (void)call_void(env, keystore, "deleteEntry", "(Ljava/lang/String;)V", alias);
    frame_end(env);
}
void zapp_devkey_jni_ops(struct zapp_devkey_ops *ops, struct zapp_devkey_jni *state)
{
    /* No random hook: the module draws from getrandom. */
    *ops = (struct zapp_devkey_ops){state, NULL, jni_device_secure, jni_create_key, jni_key_level,
                                    jni_seal, jni_open, jni_delete_key};
}

bool zapp_devkey_confirm_credential(JNIEnv *env, jobject activity)
{
    if (!frame_begin(env)) return false;
    jstring name = (*env)->NewStringUTF(env, "keyguard");
    jobject guard = name ? call_object(env, activity, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;", name) : NULL;
    jstring title = zj_clean(env) ? (*env)->NewStringUTF(env, "Unlock Z23 wallet") : NULL;
    jobject intent = guard && title ? call_object(env, guard, "createConfirmDeviceCredentialIntent",
        "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/Intent;", title, NULL) : NULL;
    bool started = zj_clean(env) && intent && call_void(env, activity, "startActivity", "(Landroid/content/Intent;)V", intent);
    frame_end(env);
    return started;
}
