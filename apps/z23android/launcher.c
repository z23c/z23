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
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    bool ok = start_activity(env, activity, new_intent(env, "android.settings.HOME_SETTINGS"));
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
bool zapp_launcher_start(JNIEnv *env, jobject activity, const char *package)
{
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject manager = zj_object_property(env, activity, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jmethodID get = manager ? zj_method(env, manager, "getLaunchIntentForPackage", "(Ljava/lang/String;)Landroid/content/Intent;") : NULL;
    jstring name = get ? (*env)->NewStringUTF(env, package) : NULL;
    jobject intent = name ? (*env)->CallObjectMethod(env, manager, get, name) : NULL;
    bool ok = zj_clean(env) && intent && start_activity(env, activity, intent);
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
/* Reads the package name of a ResolveInfo into out. */
static bool resolve_package(JNIEnv *env, jobject info, char *out, size_t cap)
{
    jclass cls = (*env)->GetObjectClass(env, info);
    jfieldID activity_field = zj_clean(env) && cls ? (*env)->GetFieldID(env, cls, "activityInfo", "Landroid/content/pm/ActivityInfo;") : NULL;
    jobject activity_info = activity_field ? (*env)->GetObjectField(env, info, activity_field) : NULL;
    jclass info_cls = zj_clean(env) && activity_info ? (*env)->GetObjectClass(env, activity_info) : NULL;
    jfieldID package_field = info_cls ? (*env)->GetFieldID(env, info_cls, "packageName", "Ljava/lang/String;") : NULL;
    jstring package = package_field ? (*env)->GetObjectField(env, activity_info, package_field) : NULL;
    return zj_clean(env) && package && zj_copy_utf(env, package, out, cap);
}
/* Reads the label of a ResolveInfo into out; false when the app has no readable label. */
static bool resolve_label(JNIEnv *env, jobject info, jobject manager, char *out, size_t cap)
{
    jmethodID load = zj_method(env, info, "loadLabel", "(Landroid/content/pm/PackageManager;)Ljava/lang/CharSequence;");
    jobject label = load ? (*env)->CallObjectMethod(env, info, load, manager) : NULL;
    jmethodID to_string = zj_clean(env) && label ? zj_method(env, label, "toString", "()Ljava/lang/String;") : NULL;
    jstring text = to_string ? (*env)->CallObjectMethod(env, label, to_string) : NULL;
    return zj_clean(env) && text && zj_copy_utf(env, text, out, cap);
}
static jobject resolve_icon(JNIEnv *env, jobject info, jobject manager)
{
    jmethodID load = zj_method(env, info, "loadIcon", "(Landroid/content/pm/PackageManager;)Landroid/graphics/drawable/Drawable;");
    jobject icon = load ? (*env)->CallObjectMethod(env, info, load, manager) : NULL;
    return zj_clean(env) ? icon : NULL;
}
static bool read_entry(JNIEnv *env, jobject info, jobject manager, const char *own, struct zapp_launcher_app *app, bool icons)
{
    if ((*env)->PushLocalFrame(env, 16) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject icon = NULL;
    memset(app, 0, sizeof(*app));
    bool ok = resolve_package(env, info, app->entry.package, sizeof(app->entry.package)) && strcmp(app->entry.package, own) &&
        resolve_label(env, info, manager, app->entry.label, sizeof(app->entry.label));
    if (ok && icons) icon = resolve_icon(env, info, manager);
    if (icon && !zj_keep(env, &app->icon, icon)) app->icon = NULL;
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
static int by_label(const void *a, const void *b)
{
    const struct zapp_launcher_app *x = a, *y = b;
    int order = strcasecmp(x->entry.label, y->entry.label);
    return order ? order : strcmp(x->entry.package, y->entry.package);
}
static bool own_package(JNIEnv *env, jobject activity, char *out, size_t cap)
{
    jstring name = (jstring)zj_object_property(env, activity, "getPackageName", "()Ljava/lang/String;");
    return name && zj_copy_utf(env, name, out, cap);
}
size_t zapp_launcher_list(JNIEnv *env, jobject activity, struct zapp_launcher_app *apps, size_t max, bool icons)
{
    size_t count = 0;
    char own[ZAPP_APP_PACKAGE_CAP] = "";
    if (max > ZAPP_LAUNCHER_MAX) max = ZAPP_LAUNCHER_MAX;
    if ((*env)->PushLocalFrame(env, 32) != JNI_OK) { (void)zj_clean(env); return 0; }
    jobject manager = zj_object_property(env, activity, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject list = manager && own_package(env, activity, own, sizeof(own)) ? query_launchers(env, manager) : NULL;
    jmethodID size = list ? zj_method(env, list, "size", "()I") : NULL;
    jmethodID get = size ? zj_method(env, list, "get", "(I)Ljava/lang/Object;") : NULL;
    jint total = get ? (*env)->CallIntMethod(env, list, size) : 0;
    for (jint i = 0; zj_clean(env) && i < total && count < max; ++i) {
        jobject info = (*env)->CallObjectMethod(env, list, get, i);
        if (zj_clean(env) && info && read_entry(env, info, manager, own, &apps[count], icons)) ++count;
        if (info) (*env)->DeleteLocalRef(env, info);
    }
    (*env)->PopLocalFrame(env, NULL);
    qsort(apps, count, sizeof(*apps), by_label);
    return count;
}
void zapp_launcher_release(JNIEnv *env, struct zapp_launcher_app *apps, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        if (apps[i].icon) (*env)->DeleteGlobalRef(env, apps[i].icon);
        apps[i].icon = NULL;
    }
}
