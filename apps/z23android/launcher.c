/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "launcher.h"
#include "jni_util.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static jobject new_intent(JNIEnv *env, const char *action)
{
    jclass cls = (*env)->FindClass(env, "android/content/Intent");
    jmethodID ctor = zj_clean(env) && cls ? (*env)->GetMethodID(env, cls, "<init>", "(Ljava/lang/String;)V") : NULL;
    jstring name = ctor ? (*env)->NewStringUTF(env, action) : NULL;
    jobject intent = name ? (*env)->NewObject(env, cls, ctor, name) : NULL;
    return zj_clean(env) ? intent : NULL;
}
static bool start_activity(JNIEnv *env, jobject activity, jobject intent)
{
    jmethodID start = intent ? zj_method(env, activity, "startActivity", "(Landroid/content/Intent;)V") : NULL;
    if (!start) return false;
    (*env)->CallVoidMethod(env, activity, start, intent);
    return zj_clean(env);
}
bool zapp_launcher_home_settings(JNIEnv *env, jobject activity)
{
    static const char *const actions[] = {"android.settings.HOME_SETTINGS", "android.settings.SETTINGS"};
    bool ok = false;
    for (size_t i = 0; !ok && i < sizeof(actions) / sizeof(actions[0]); ++i) {
        if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
        ok = start_activity(env, activity, new_intent(env, actions[i]));
        (*env)->PopLocalFrame(env, NULL);
    }
    return ok;
}
/* A MAIN/LAUNCHER intent for one activity class of a package, opened in a new task. */
static jobject component_intent(JNIEnv *env, const char *package, const char *activity_class)
{
    jobject intent = new_intent(env, "android.intent.action.MAIN");
    jmethodID category = intent ? zj_method(env, intent, "addCategory", "(Ljava/lang/String;)Landroid/content/Intent;") : NULL;
    jstring name = category ? (*env)->NewStringUTF(env, "android.intent.category.LAUNCHER") : NULL;
    if (name) (*env)->CallObjectMethod(env, intent, category, name);
    jmethodID set = name && zj_clean(env) ? zj_method(env, intent, "setClassName", "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;") : NULL;
    jstring pkg = set ? (*env)->NewStringUTF(env, package) : NULL;
    jstring cls = pkg ? (*env)->NewStringUTF(env, activity_class) : NULL;
    if (cls) (*env)->CallObjectMethod(env, intent, set, pkg, cls);
    jmethodID flags = cls && zj_clean(env) ? zj_method(env, intent, "addFlags", "(I)Landroid/content/Intent;") : NULL;
    if (flags) (*env)->CallObjectMethod(env, intent, flags, (jint)0x10000000);
    bool clear = zj_clean(env);
    return flags && clear ? intent : NULL;
}
bool zapp_launcher_start(JNIEnv *env, jobject activity, const char *package, const char *activity_class)
{
    if ((*env)->PushLocalFrame(env, 16) != JNI_OK) { (void)zj_clean(env); return false; }
    bool ok = package[0] && activity_class[0] && start_activity(env, activity, component_intent(env, package, activity_class));
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
/* The launcher activities of installed apps, as a java.util.List of ResolveInfo, or NULL. */
static jobject query_launchers(JNIEnv *env, jobject manager)
{
    jobject intent = new_intent(env, "android.intent.action.MAIN");
    jmethodID category = intent ? zj_method(env, intent, "addCategory", "(Ljava/lang/String;)Landroid/content/Intent;") : NULL;
    jstring name = category ? (*env)->NewStringUTF(env, "android.intent.category.LAUNCHER") : NULL;
    if (name) (*env)->CallObjectMethod(env, intent, category, name);
    jmethodID query = name && zj_clean(env) ? zj_method(env, manager, "queryIntentActivities", "(Landroid/content/Intent;I)Ljava/util/List;") : NULL;
    jobject list = query ? (*env)->CallObjectMethod(env, manager, query, intent, 0) : NULL;
    return zj_clean(env) ? list : NULL;
}
static bool string_field(JNIEnv *env, jobject object, jclass cls, const char *field, char *out, size_t cap)
{
    jfieldID id = (*env)->GetFieldID(env, cls, field, "Ljava/lang/String;");
    jstring value = zj_clean(env) && id ? (*env)->GetObjectField(env, object, id) : NULL;
    return zj_clean(env) && value && zj_copy_utf(env, value, out, cap);
}
/* Reads the package name and launcher activity class of a ResolveInfo. */
static bool resolve_names(JNIEnv *env, jobject info, struct zapp_app_entry *entry)
{
    jclass cls = (*env)->GetObjectClass(env, info);
    jfieldID activity_field = zj_clean(env) && cls ? (*env)->GetFieldID(env, cls, "activityInfo", "Landroid/content/pm/ActivityInfo;") : NULL;
    jobject activity_info = activity_field ? (*env)->GetObjectField(env, info, activity_field) : NULL;
    jclass info_cls = zj_clean(env) && activity_info ? (*env)->GetObjectClass(env, activity_info) : NULL;
    return info_cls && string_field(env, activity_info, info_cls, "packageName", entry->package, sizeof(entry->package)) &&
        string_field(env, activity_info, info_cls, "name", entry->activity, sizeof(entry->activity));
}
/* Copies the text of a CharSequence into out, cut to fit. Leaves out empty when the sequence is NULL or unreadable. */
static void char_sequence_into(JNIEnv *env, jobject sequence, char *out, size_t cap)
{
    jmethodID to_string = sequence && zj_clean(env) ? zj_method(env, sequence, "toString", "()Ljava/lang/String;") : NULL;
    jstring text = to_string ? (*env)->CallObjectMethod(env, sequence, to_string) : NULL;
    const char *chars = zj_clean(env) && text ? (*env)->GetStringUTFChars(env, text, NULL) : NULL;
    if (chars) zapp_home_fit_label(out, cap, chars);
    if (chars) (*env)->ReleaseStringUTFChars(env, text, chars);
    (void)zj_clean(env);
}
/* The value of an object field, or NULL when the field cannot be read. */
static jobject object_field(JNIEnv *env, jobject object, const char *name, const char *sig)
{
    jclass cls = object && zj_clean(env) ? (*env)->GetObjectClass(env, object) : NULL;
    jfieldID id = cls ? (*env)->GetFieldID(env, cls, name, sig) : NULL;
    jobject value = id ? (*env)->GetObjectField(env, object, id) : NULL;
    return zj_clean(env) ? value : NULL;
}
/* Reads the app's declared (non-localized) name into out, or leaves out empty when it has none. */
static void resolve_declared(JNIEnv *env, jobject info, char *out, size_t cap)
{
    jobject activity_info = object_field(env, info, "activityInfo", "Landroid/content/pm/ActivityInfo;");
    jobject app_info = object_field(env, activity_info, "applicationInfo", "Landroid/content/pm/ApplicationInfo;");
    char_sequence_into(env, object_field(env, app_info, "nonLocalizedLabel", "Ljava/lang/CharSequence;"), out, cap);
}
/* Reads the label of a ResolveInfo into out. An empty label falls back to the declared name, then to the package's last
 * part, so every listed app has a readable name. */
static void resolve_label(JNIEnv *env, jobject info, jobject manager, const char *package, char *out, size_t cap)
{
    char declared[ZAPP_APP_LABEL_CAP] = "";
    jmethodID load = zj_method(env, info, "loadLabel", "(Landroid/content/pm/PackageManager;)Ljava/lang/CharSequence;");
    jobject label = load ? (*env)->CallObjectMethod(env, info, load, manager) : NULL;
    char_sequence_into(env, label, out, cap);
    if (!out[0]) resolve_declared(env, info, declared, sizeof(declared));
    zapp_home_fallback_label(out, cap, declared, package);
}
/* Whether two installed packages are signed with the same key. */
static bool same_signature(JNIEnv *env, jobject manager, const char *own, const char *other)
{
    jmethodID check = zj_method(env, manager, "checkSignatures", "(Ljava/lang/String;Ljava/lang/String;)I");
    jstring a = check ? (*env)->NewStringUTF(env, own) : NULL;
    jstring b = a ? (*env)->NewStringUTF(env, other) : NULL;
    jint result = b ? (*env)->CallIntMethod(env, manager, check, a, b) : -1;
    return zj_clean(env) && result == 0;
}
/* A long versionName is cut on a character boundary. Dropping it would show the code as if the name were absent. */
static void copy_version_name(JNIEnv *env, jobject info, struct zapp_app_entry *entry)
{
    jclass cls = info ? (*env)->GetObjectClass(env, info) : NULL;
    jfieldID id = zj_clean(env) && cls ? (*env)->GetFieldID(env, cls, "versionName", "Ljava/lang/String;") : NULL;
    jstring value = zj_clean(env) && id ? (*env)->GetObjectField(env, info, id) : NULL;
    const char *chars = zj_clean(env) && value ? (*env)->GetStringUTFChars(env, value, NULL) : NULL;
    if (chars) zapp_home_store_version_name(entry, chars);
    if (chars) (*env)->ReleaseStringUTFChars(env, value, chars);
    (void)zj_clean(env);
}
/* Reads an installed Z23 app's version without treating it as source identity. */
static void resolve_version(JNIEnv *env, jobject manager, struct zapp_app_entry *entry)
{
    if (!entry->same_signature || (*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return; }
    jstring package = (*env)->NewStringUTF(env, entry->package);
    jmethodID get = package ? zj_method(env, manager, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;") : NULL;
    jobject info = get ? (*env)->CallObjectMethod(env, manager, get, package, 0) : NULL;
    jmethodID code = info ? zj_method(env, info, "getLongVersionCode", "()J") : NULL;
    jlong value = code ? (*env)->CallLongMethod(env, info, code) : -1;
    entry->version_code = (int64_t)value;
    entry->version_known = zj_clean(env) && value >= 0;
    if (entry->version_known) copy_version_name(env, info, entry);
    (*env)->PopLocalFrame(env, NULL);
}
static bool read_entry(JNIEnv *env, jobject info, jobject manager, const char *own, struct zapp_launcher_app *app)
{
    if ((*env)->PushLocalFrame(env, 16) != JNI_OK) { (void)zj_clean(env); return false; }
    memset(app, 0, sizeof(*app));
    bool ok = resolve_names(env, info, &app->entry);
    bool current = ok && !strcmp(app->entry.package, own);
    if (ok) resolve_label(env, info, manager, app->entry.package, app->entry.label, sizeof(app->entry.label));
    if (ok && (current || zapp_home_is_z23_app(app->entry.package))) {
        app->entry.same_signature = current || same_signature(env, manager, own, app->entry.package);
        resolve_version(env, manager, &app->entry);
    }
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
static int by_label(const void *a, const void *b)
{
    const struct zapp_launcher_app *x = a, *y = b;
    return zapp_home_app_compare(&x->entry, &y->entry);
}
static bool own_package(JNIEnv *env, jobject activity, char *out, size_t cap)
{
    jstring name = (jstring)zj_object_property(env, activity, "getPackageName", "()Ljava/lang/String;");
    return name && zj_copy_utf(env, name, out, cap);
}
static size_t collect_launchers(JNIEnv *env, jobject manager, jobject list, const char *own,
    struct zapp_launcher_app *apps, size_t max)
{
    size_t count = 0;
    jmethodID size = list ? zj_method(env, list, "size", "()I") : NULL;
    jmethodID get = size ? zj_method(env, list, "get", "(I)Ljava/lang/Object;") : NULL;
    jint total = get ? (*env)->CallIntMethod(env, list, size) : 0;
    bool have_base = false;
    for (jint i = 0; zj_clean(env) && i < total && (count < max || !have_base); ++i) {
        jobject info = (*env)->CallObjectMethod(env, list, get, i);
        struct zapp_launcher_app app;
        if (zj_clean(env) && info && read_entry(env, info, manager, own, &app)) {
            bool base = !strcmp(app.entry.package, "org.z23.nativeapp");
            size_t slot = zapp_home_app_slot(&app.entry, count, max, have_base);
            if (base) have_base = true;
            if (slot < count) apps[slot] = app;
            else if (slot < max) apps[count++] = app;
        }
        if (info) (*env)->DeleteLocalRef(env, info);
    }
    return count;
}
size_t zapp_launcher_list(JNIEnv *env, jobject activity, struct zapp_launcher_app *apps, size_t max)
{
    char own[ZAPP_APP_PACKAGE_CAP] = "";
    if (max > ZAPP_LAUNCHER_MAX) max = ZAPP_LAUNCHER_MAX;
    if (!max) return 0;
    if ((*env)->PushLocalFrame(env, 32) != JNI_OK) { (void)zj_clean(env); return 0; }
    jobject manager = zj_object_property(env, activity, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject list = manager && own_package(env, activity, own, sizeof(own)) ? query_launchers(env, manager) : NULL;
    size_t count = collect_launchers(env, manager, list, own, apps, max);
    (*env)->PopLocalFrame(env, NULL);
    qsort(apps, count, sizeof(*apps), by_label);
    return count;
}
