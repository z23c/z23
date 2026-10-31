/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "device_key.h"
#include "base/cleanse.h"
#include "jni_util.h"
#include <stdarg.h>
#include <pthread.h>
#include <string.h>

#define ALIAS "z23.wallet.device-key.v2"
#define OLD_ALIAS "z23.wallet.device-key.v1"
#define AAD "z23.wallet.device-key.v2"
#define PROMPT_CLASS "org.z23.nativeapp.KeyPrompt"
#define PROMPT_TIMEOUT_MS 120000u
/* Per-operation authentication: no validity window. Keystore binds each operation to one fresh
 * authentication or refuses it. */
#define AUTH_EVERY_USE 0
#define MIN_API 30
/* BiometricManager.Authenticators.BIOMETRIC_STRONG | DEVICE_CREDENTIAL, the same two sources as AUTH_TYPES. */
#define PROMPT_AUTHENTICATORS 0x800F
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
        builder_step(env, builder, "setUserAuthenticationParameters", BUILDER_SIG("II"), AUTH_EVERY_USE, AUTH_TYPES) &&
        builder_step(env, builder, "setUnlockedDeviceRequired", BUILDER_SIG("Z"), JNI_TRUE) &&
        builder_step(env, builder, "setInvalidatedByBiometricEnrollment", BUILDER_SIG("Z"), JNI_FALSE) &&
        builder_step(env, builder, "setIsStrongBoxBacked", BUILDER_SIG("Z"), strongbox ? JNI_TRUE : JNI_FALSE);
    jobject spec = ok ? call_object(env, builder, "build", "()Landroid/security/keystore/KeyGenParameterSpec;") : NULL;
    return zj_clean(env) ? spec : NULL;
}
/* Build.VERSION.SDK_INT, or 0 when it cannot be read. */
static jint api_level(JNIEnv *env)
{
    jclass version = (*env)->FindClass(env, "android/os/Build$VERSION");
    jfieldID field = zj_clean(env) && version ? (*env)->GetStaticFieldID(env, version, "SDK_INT", "I") : NULL;
    jint level = field ? (*env)->GetStaticIntField(env, version, field) : 0;
    return zj_clean(env) ? level : 0;
}
/* Per-operation authentication with a device credential needs API 30. An older release gets no key. */
static status_t jni_create_key(void *context, bool strongbox)
{
    JNIEnv *env = ((struct zapp_devkey_jni *)context)->env;
    status_t st = ZAPP_DEVKEY_ERROR;
    if (!frame_begin(env)) return ZAPP_DEVKEY_ERROR;
    if (api_level(env) < MIN_API) { frame_end(env); return ZAPP_DEVKEY_ERROR; }
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
static bool info_int(JNIEnv *env, jobject info, const char *name, jint *value)
{
    jmethodID get = zj_method(env, info, name, "()I");
    *value = get ? (*env)->CallIntMethod(env, info, get) : 0;
    return get && zj_clean(env);
}
static bool info_flag(JNIEnv *env, jobject info, const char *name, bool *value)
{
    jmethodID get = zj_method(env, info, name, "()Z");
    *value = get && (*env)->CallBooleanMethod(env, info, get);
    return get && zj_clean(env);
}
/* Reads the security level and the authentication policy of the stored key from its KeyInfo. The key
 * is per-use only when authentication is required with no validity window, for both sources, and
 * the secure hardware enforces it. */
static bool key_info_policy(JNIEnv *env, jobject key, enum zapp_devkey_level *level, bool *per_use)
{
    jclass factory = (*env)->FindClass(env, "javax/crypto/SecretKeyFactory");
    jclass info_cls = zj_clean(env) && factory ? (*env)->FindClass(env, "android/security/keystore/KeyInfo") : NULL;
    jstring algorithm = zj_clean(env) && info_cls ? (*env)->NewStringUTF(env, "AES") : NULL;
    jstring provider = algorithm ? (*env)->NewStringUTF(env, "AndroidKeyStore") : NULL;
    jobject maker = provider ? call_static(env, factory, "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;", algorithm, provider) : NULL;
    jobject info = zj_clean(env) && maker ? call_object(env, maker, "getKeySpec",
        "(Ljavax/crypto/SecretKey;Ljava/lang/Class;)Ljava/security/spec/KeySpec;", key, info_cls) : NULL;
    jint security = 0, seconds = 0, types = 0;
    bool required = false, enforced = false;
    bool read = zj_clean(env) && info && info_int(env, info, "getSecurityLevel", &security) &&
        info_flag(env, info, "isUserAuthenticationRequired", &required) &&
        info_int(env, info, "getUserAuthenticationValidityDurationSeconds", &seconds) &&
        info_int(env, info, "getUserAuthenticationType", &types) &&
        info_flag(env, info, "isUserAuthenticationRequirementEnforcedBySecureHardware", &enforced);
    if (!read) return false;
    *level = level_of(security);
    *per_use = required && seconds == AUTH_EVERY_USE && types == AUTH_TYPES && enforced;
    return true;
}
static status_t jni_key_policy(void *context, enum zapp_devkey_level *level, bool *per_use)
{
    JNIEnv *env = ((struct zapp_devkey_jni *)context)->env;
    status_t st = ZAPP_DEVKEY_ERROR;
    if (!frame_begin(env)) return st;
    jobject key = stored_key(env, &st);
    if (key) st = key_info_policy(env, key, level, per_use) ? ZAPP_DEVKEY_OK : ZAPP_DEVKEY_ERROR;
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

/* The prompt in flight. The answering callbacks run on a Java executor thread and the abandon hook on
 * the UI thread; the references and the ticket they match against are guarded by refs_lock. A
 * callback object that is not the current one belongs to an earlier, finished prompt and is ignored. */
static struct zapp_devkey_wait prompt_wait = ZAPP_DEVKEY_WAIT_INIT;
static pthread_mutex_t refs_lock = PTHREAD_MUTEX_INITIALIZER;
static jclass prompt_class;
static jobject current_callback, current_cancel;
static unsigned long current_ticket;

static void answer_from(JNIEnv *env, jobject self, enum zapp_devkey_answer answer)
{
    pthread_mutex_lock(&refs_lock);
    bool mine = current_callback && (*env)->IsSameObject(env, self, current_callback);
    unsigned long ticket = current_ticket;
    pthread_mutex_unlock(&refs_lock);
    if (mine) (void)zapp_devkey_wait_answer(&prompt_wait, ticket, answer);
}
/* Implementations of the two native methods of org.z23.nativeapp.KeyPrompt. They only record the
 * answer and wake the waiting worker: no wallet logic and no key material runs on the callback thread. */
static void prompt_succeeded(JNIEnv *env, jobject self, jobject result)
{
    (void)result;
    answer_from(env, self, ZAPP_DEVKEY_ANSWER_SUCCEEDED);
}
static void prompt_error(JNIEnv *env, jobject self, jint code, jobject text)
{
    (void)text;
    answer_from(env, self, zapp_devkey_answer_for_error(code));
}
/* The KeyPrompt class, loaded through the activity's class loader (the dex lives in the app, not on
 * the system loader that FindClass uses from a native thread) with its natives registered once. */
static jclass load_prompt_class(JNIEnv *env, jobject activity)
{
    static const JNINativeMethod natives[] = {
        {"onAuthenticationSucceeded", "(Landroid/hardware/biometrics/BiometricPrompt$AuthenticationResult;)V", (void *)prompt_succeeded},
        {"onAuthenticationError", "(ILjava/lang/CharSequence;)V", (void *)prompt_error}};
    pthread_mutex_lock(&refs_lock);
    jclass local = prompt_class ? (*env)->NewLocalRef(env, prompt_class) : NULL;
    if (!local) {
        jobject loader = call_object(env, activity, "getClassLoader", "()Ljava/lang/ClassLoader;");
        jstring name = zj_clean(env) && loader ? (*env)->NewStringUTF(env, PROMPT_CLASS) : NULL;
        jclass found = name ? (jclass)call_object(env, loader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", name) : NULL;
        if (zj_clean(env) && found && (*env)->RegisterNatives(env, found, natives, 2) == JNI_OK && zj_clean(env)) {
            prompt_class = (*env)->NewGlobalRef(env, found);
            local = found;
        }
        (void)zj_clean(env);
    }
    pthread_mutex_unlock(&refs_lock);
    return local;
}
static const char *purpose_title(enum zapp_devkey_purpose purpose)
{
    switch (purpose) {
    case ZAPP_DEVKEY_PURPOSE_CREATE: return "Protect this wallet";
    case ZAPP_DEVKEY_PURPOSE_UNLOCK: return "Unlock this wallet";
    default: return "Authorise this payment";
    }
}
#define PROMPT_BUILDER "android/hardware/biometrics/BiometricPrompt$Builder"
/* The system prompt for the purpose, over fixed text only. */
static jobject build_prompt(JNIEnv *env, jobject activity, enum zapp_devkey_purpose purpose)
{
    jstring title = (*env)->NewStringUTF(env, purpose_title(purpose));
    jobject builder = title ? new_object(env, PROMPT_BUILDER, "(Landroid/content/Context;)V", activity) : NULL;
    bool ok = builder &&
        builder_step(env, builder, "setTitle", "(Ljava/lang/CharSequence;)L" PROMPT_BUILDER ";", title) &&
        builder_step(env, builder, "setAllowedAuthenticators", "(I)L" PROMPT_BUILDER ";", PROMPT_AUTHENTICATORS);
    jobject prompt = ok ? call_object(env, builder, "build", "()Landroid/hardware/biometrics/BiometricPrompt;") : NULL;
    return zj_clean(env) ? prompt : NULL;
}
/* Shows one BiometricPrompt over a CryptoObject that holds the initialised cipher and waits for the
 * owner. OK means Keystore has bound this one operation to a fresh authentication; the caller then
 * runs the operation on the same cipher. Nothing the callbacks do touches key material. */
static status_t authenticate_once(JNIEnv *env, jobject activity, jobject cipher, enum zapp_devkey_purpose purpose)
{
    jclass klass = load_prompt_class(env, activity);
    jobject prompt = klass ? build_prompt(env, activity, purpose) : NULL;
    jobject crypto = prompt ? new_object(env, "android/hardware/biometrics/BiometricPrompt$CryptoObject", "(Ljavax/crypto/Cipher;)V", cipher) : NULL;
    jobject cancel = crypto ? new_object(env, "android/os/CancellationSignal", "()V") : NULL;
    jclass pool = cancel ? (*env)->FindClass(env, "java/util/concurrent/Executors") : NULL;
    jobject executor = zj_clean(env) && pool ? call_static(env, pool, "newSingleThreadExecutor", "()Ljava/util/concurrent/ExecutorService;") : NULL;
    jmethodID construct = executor ? (*env)->GetMethodID(env, klass, "<init>", "()V") : NULL;
    jobject callback = zj_clean(env) && construct ? (*env)->NewObject(env, klass, construct) : NULL;
    if (!zj_clean(env) || !callback) {
        if (executor) (void)call_void(env, executor, "shutdown", "()V");
        return ZAPP_DEVKEY_ERROR;
    }
    unsigned long ticket = zapp_devkey_wait_begin(&prompt_wait);
    if (!ticket) { (void)call_void(env, executor, "shutdown", "()V"); return ZAPP_DEVKEY_ERROR; }
    pthread_mutex_lock(&refs_lock);
    current_callback = (*env)->NewGlobalRef(env, callback);
    current_cancel = (*env)->NewGlobalRef(env, cancel);
    current_ticket = ticket;
    pthread_mutex_unlock(&refs_lock);
    if (!call_void(env, prompt, "authenticate",
            "(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;Landroid/os/CancellationSignal;"
            "Ljava/util/concurrent/Executor;Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;)V",
            crypto, cancel, executor, callback)) {
        (void)zj_clean(env);
        (void)zapp_devkey_wait_answer(&prompt_wait, ticket, ZAPP_DEVKEY_ANSWER_FAILED);
    }
    enum zapp_devkey_answer answer = zapp_devkey_wait_end(&prompt_wait, ticket, PROMPT_TIMEOUT_MS);
    if (answer == ZAPP_DEVKEY_ANSWER_TIMED_OUT) (void)call_void(env, cancel, "cancel", "()V");
    pthread_mutex_lock(&refs_lock);
    jobject stale_callback = current_callback, stale_cancel = current_cancel;
    current_callback = current_cancel = NULL;
    current_ticket = 0;
    pthread_mutex_unlock(&refs_lock);
    if (stale_callback) (*env)->DeleteGlobalRef(env, stale_callback);
    if (stale_cancel) (*env)->DeleteGlobalRef(env, stale_cancel);
    (void)call_void(env, executor, "shutdown", "()V");
    (void)zj_clean(env);
    return zapp_devkey_status_for_answer(answer);
}
void zapp_devkey_jni_abandon(JNIEnv *env)
{
    pthread_mutex_lock(&refs_lock);
    jobject cancel = current_cancel ? (*env)->NewLocalRef(env, current_cancel) : NULL;
    pthread_mutex_unlock(&refs_lock);
    (void)zapp_devkey_wait_abandon(&prompt_wait);
    if (cancel) {
        (void)call_void(env, cancel, "cancel", "()V");
        (*env)->DeleteLocalRef(env, cancel);
    }
    (void)zj_clean(env);
}

static status_t jni_seal(void *context, const uint8_t *plain, size_t len, uint8_t iv[ZAPP_DEVKEY_IV], uint8_t sealed[ZAPP_DEVKEY_SEALED])
{
    struct zapp_devkey_jni *state = context;
    JNIEnv *env = state->env;
    status_t st = ZAPP_DEVKEY_ERROR;
    if (!frame_begin(env)) return st;
    jobject key = stored_key(env, &st);
    jobject cipher = key ? cipher_for(env, 1, key, NULL) : NULL;
    if (key && !cipher) st = failed(env);
    if (cipher) st = authenticate_once(env, state->activity, cipher, ZAPP_DEVKEY_PURPOSE_CREATE);
    jbyteArray input = st == ZAPP_DEVKEY_OK ? bytes_new(env, plain, len) : NULL;
    jbyteArray output = input ? cipher_run(env, cipher, input) : NULL;
    if (input && !output) st = failed(env);
    bytes_wipe(env, input);
    if (output) st = seal_copy(env, cipher, output, iv, sealed) ? ZAPP_DEVKEY_OK : ZAPP_DEVKEY_ERROR;
    else if (st == ZAPP_DEVKEY_OK) st = ZAPP_DEVKEY_ERROR;
    frame_end(env);
    return st;
}
static status_t jni_open(void *context, enum zapp_devkey_purpose purpose, const uint8_t iv[ZAPP_DEVKEY_IV],
                         const uint8_t sealed[ZAPP_DEVKEY_SEALED], uint8_t *plain, size_t cap)
{
    struct zapp_devkey_jni *state = context;
    JNIEnv *env = state->env;
    status_t st = ZAPP_DEVKEY_ERROR;
    if (!frame_begin(env)) return st;
    jobject key = stored_key(env, &st);
    jbyteArray nonce = key ? bytes_new(env, iv, ZAPP_DEVKEY_IV) : NULL;
    jobject params = nonce ? new_object(env, "javax/crypto/spec/GCMParameterSpec", "(I[B)V", 128, nonce) : NULL;
    bytes_wipe(env, nonce);
    jobject cipher = params ? cipher_for(env, 2, key, params) : NULL;
    if (params && !cipher) st = failed(env);
    if (cipher) st = authenticate_once(env, state->activity, cipher, purpose);
    jbyteArray input = st == ZAPP_DEVKEY_OK ? bytes_new(env, sealed, ZAPP_DEVKEY_SEALED) : NULL;
    jbyteArray output = input ? cipher_run(env, cipher, input) : NULL;
    if (input && !output) st = failed(env);
    bytes_wipe(env, input);
    if (output) st = bytes_take(env, output, plain, cap) ? ZAPP_DEVKEY_OK : ZAPP_DEVKEY_ERROR;
    else if (st == ZAPP_DEVKEY_OK) st = ZAPP_DEVKEY_ERROR;
    frame_end(env);
    return st;
}
/* Removes the current key and the key of the earlier 30 second window design, if one is left. */
static void jni_delete_key(void *context)
{
    static const char *const aliases[] = {ALIAS, OLD_ALIAS};
    JNIEnv *env = ((struct zapp_devkey_jni *)context)->env;
    if (!frame_begin(env)) return;
    jclass store = (*env)->FindClass(env, "java/security/KeyStore");
    jstring type = zj_clean(env) ? (*env)->NewStringUTF(env, "AndroidKeyStore") : NULL;
    jobject keystore = type ? call_static(env, store, "getInstance", "(Ljava/lang/String;)Ljava/security/KeyStore;", type) : NULL;
    bool loaded = keystore && call_void(env, keystore, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V", NULL);
    for (size_t at = 0; loaded && at < sizeof(aliases) / sizeof(aliases[0]); ++at) {
        jstring alias = (*env)->NewStringUTF(env, aliases[at]);
        if (alias) (void)call_void(env, keystore, "deleteEntry", "(Ljava/lang/String;)V", alias);
    }
    frame_end(env);
}
void zapp_devkey_jni_ops(struct zapp_devkey_ops *ops, struct zapp_devkey_jni *state)
{
    /* No random hook: the module draws from getrandom. */
    *ops = (struct zapp_devkey_ops){state, NULL, jni_device_secure, jni_create_key, jni_key_policy,
                                    jni_seal, jni_open, jni_delete_key};
}
