/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "native_ui.h"
#include "base/cleanse.h"
#include "fleet.h"
#include "hosts.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static jobject root, status_view, result_view, prompt_view, invite_view, camera_view, balance_view;
static jobject connection_view, transcript_view, fleet_view, receipt_view, details_view, notice_view;
static jobject voice_view, pair_view, hosts_view, sync_view;
static jobject buttons[16];
static enum zapp_voice_state voice_state;
static bool details_open;
static enum zapp_reply_state reply_state;
static zapp_native_action callback;
static int pressed = -1;
static float down_x, down_y;
static char last_receipt[8192];
static float density = 1.0f;
static bool voice_preview;
static const char *const actions[] = {"node_start", "node_stop", NULL, "chat", "fleet_scan", "fleet_preview", "fleet_join"};

static bool clean(JNIEnv *env)
{
    if (!(*env)->ExceptionCheck(env)) return true;
    (*env)->ExceptionClear(env); return false;
}
static int dp(float value) { return (int)(value * density + 0.5f); }
static bool int_property(JNIEnv *env, jobject view, const char *name, jint value)
{
    jclass cls = (*env)->GetObjectClass(env, view);
    jmethodID method = clean(env) && cls ? (*env)->GetMethodID(env, cls, name, "(I)V") : NULL;
    bool ok = clean(env) && method;
    if (ok) { (*env)->CallVoidMethod(env, view, method, value); ok = clean(env); }
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return ok;
}
static bool bool_property(JNIEnv *env, jobject view, const char *name, bool value)
{
    jclass cls = (*env)->GetObjectClass(env, view);
    jmethodID method = clean(env) && cls ? (*env)->GetMethodID(env, cls, name, "(Z)V") : NULL;
    bool ok = clean(env) && method;
    if (ok) { (*env)->CallVoidMethod(env, view, method, (jboolean)value); ok = clean(env); }
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return ok;
}
static bool padding(JNIEnv *env, jobject view, int horizontal, int vertical)
{
    jclass cls = (*env)->GetObjectClass(env, view);
    jmethodID method = clean(env) && cls ? (*env)->GetMethodID(env, cls, "setPadding", "(IIII)V") : NULL;
    bool ok = clean(env) && method;
    if (ok) {
        (*env)->CallVoidMethod(env, view, method, dp((float)horizontal), dp((float)vertical),
                              dp((float)horizontal), dp((float)vertical));
        ok = clean(env);
    }
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return ok;
}
static bool typography(JNIEnv *env, jobject view, float sp, jint color)
{
    jclass cls = (*env)->GetObjectClass(env, view);
    jmethodID size = clean(env) && cls ? (*env)->GetMethodID(env, cls, "setTextSize", "(F)V") : NULL;
    bool ok = clean(env) && size;
    if (ok) { (*env)->CallVoidMethod(env, view, size, sp); ok = clean(env); }
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return ok && int_property(env, view, "setTextColor", color);
}
/* Looks up a method on the object's class and releases the class reference. */
static jmethodID method_of(JNIEnv *env, jobject obj, const char *name, const char *sig)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID method = clean(env) && cls ? (*env)->GetMethodID(env, cls, name, sig) : NULL;
    bool found = clean(env) && method;
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return found ? method : NULL;
}
static jobject object_property(JNIEnv *env, jobject obj, const char *name, const char *sig)
{
    jmethodID method = method_of(env, obj, name, sig);
    jobject value = method ? (*env)->CallObjectMethod(env, obj, method) : NULL;
    return clean(env) ? value : NULL;
}
static bool read_density(JNIEnv *env, jobject display)
{
    jclass cls = (*env)->GetObjectClass(env, display);
    jfieldID field = clean(env) && cls ? (*env)->GetFieldID(env, cls, "density", "F") : NULL;
    if (!clean(env) || !field) return false;
    density = (*env)->GetFloatField(env, display, field);
    return clean(env) && density > 0.0f && density < 16.0f;
}
static bool load_density(JNIEnv *env, jobject activity)
{
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)clean(env); return false; }
    jobject resources = object_property(env, activity, "getResources", "()Landroid/content/res/Resources;");
    jobject display = resources ? object_property(env, resources, "getDisplayMetrics", "()Landroid/util/DisplayMetrics;") : NULL;
    bool ok = display && read_density(env, display);
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
bool zapp_native_ui_package_preview(JNIEnv *env, jobject activity, bool *preview)
{
    if ((*env)->PushLocalFrame(env, 4) != JNI_OK) { (void)clean(env); return false; }
    jclass cls = (*env)->GetObjectClass(env, activity);
    jmethodID get = clean(env) && cls ? (*env)->GetMethodID(env, cls, "getPackageName", "()Ljava/lang/String;") : NULL;
    jstring package = clean(env) && get ? (*env)->CallObjectMethod(env, activity, get) : NULL;
    const char *name = clean(env) && package ? (*env)->GetStringUTFChars(env, package, NULL) : NULL;
    bool ok = clean(env) && name;
    if (ok) *preview = !strncmp(name, "org.z23.voicepreview", strlen("org.z23.voicepreview"));
    if (name) (*env)->ReleaseStringUTFChars(env, package, name);
    ok = clean(env) && ok;
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
static bool load_identity(JNIEnv *env, jobject activity)
{
    return zapp_native_ui_package_preview(env, activity, &voice_preview);
}
static jobject widget(JNIEnv *env, const char *type, jobject activity)
{
    jclass cls = (*env)->FindClass(env, type);
    if (!clean(env) || !cls) return NULL;
    jmethodID ctor = (*env)->GetMethodID(env, cls, "<init>", "(Landroid/content/Context;)V");
    jobject obj = ctor ? (*env)->NewObject(env, cls, ctor, activity) : NULL;
    if (!clean(env)) obj = NULL;
    (*env)->DeleteLocalRef(env, cls); return obj;
}
static jstring make_string(JNIEnv *env, const char *value)
{
    size_t length = strlen(value);
    jclass cls = (*env)->FindClass(env, "java/lang/String");
    jmethodID ctor = cls ? (*env)->GetMethodID(env, cls, "<init>", "([BLjava/lang/String;)V") : NULL;
    jbyteArray bytes = length <= 65536 ? (*env)->NewByteArray(env, (jsize)length) : NULL;
    jstring encoding = (*env)->NewStringUTF(env, "UTF-8");
    if (bytes) (*env)->SetByteArrayRegion(env, bytes, 0, (jsize)length, (const jbyte *)value);
    jstring result = clean(env) && ctor && bytes && encoding ? (*env)->NewObject(env, cls, ctor, bytes, encoding) : NULL;
    if (encoding) (*env)->DeleteLocalRef(env, encoding);
    if (bytes) (*env)->DeleteLocalRef(env, bytes);
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return result;
}
static bool char_sequence(JNIEnv *env, jobject view, const char *method, const char *value)
{
    jclass cls = (*env)->GetObjectClass(env, view);
    if (!clean(env) || !cls) return false;
    jmethodID set = (*env)->GetMethodID(env, cls, method, "(Ljava/lang/CharSequence;)V");
    jstring string = make_string(env, value);
    bool ok = clean(env) && set && string;
    if (ok) { (*env)->CallVoidMethod(env, view, set, string); ok = clean(env); }
    if (string) (*env)->DeleteLocalRef(env, string);
    (*env)->DeleteLocalRef(env, cls); return ok;
}
static bool text(JNIEnv *env, jobject view, const char *value)
{
    return char_sequence(env, view, "setText", value);
}
static bool append(JNIEnv *env, jobject layout, jobject view)
{
    jclass cls = (*env)->GetObjectClass(env, layout);
    if (!clean(env) || !cls) return false;
    jmethodID add = (*env)->GetMethodID(env, cls, "addView", "(Landroid/view/View;)V");
    bool ok = clean(env) && add;
    if (ok) { (*env)->CallVoidMethod(env, layout, add, view); ok = clean(env); }
    (*env)->DeleteLocalRef(env, cls); return ok;
}
static bool keep(JNIEnv *env, jobject *dest, jobject value)
{
    *dest = (*env)->NewGlobalRef(env, value);
    return clean(env) && *dest;
}
static bool small_label(const char *label, const jobject *save)
{
    return save == &status_view || save == &sync_view || save == &connection_view || save == &voice_view ||
        !strncmp(label, "Voice pairing:", 14);
}
static float label_size(const char *label, const jobject *save)
{
    if (!strcmp(label, "Fleet") || !strcmp(label, "Phone node") || !strcmp(label, "Type a question") ||
        !strcmp(label, "Fleet invitation")) return 18.0f;
    return small_label(label, save) ? 14.0f : 16.0f;
}
static bool add_text(JNIEnv *env, jobject layout, jobject activity, const char *label, jobject *save)
{
    jobject view = widget(env, "android/widget/TextView", activity);
    bool ok = view && typography(env, view, label_size(label, save), (jint)0xff262b2b) && padding(env, view, 0, 4) &&
        text(env, view, label) && append(env, layout, view) && (!save || keep(env, save, view));
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
static bool style_button(JNIEnv *env, jobject view, size_t i, bool primary)
{
    int min_height = dp(i == 9 ? 72.0f : 48.0f);
    return typography(env, view, 16.0f, primary ? (jint)0xffffffff : (jint)0xff264a43) &&
        bool_property(env, view, "setAllCaps", false) &&
        int_property(env, view, "setMinHeight", min_height) &&
        int_property(env, view, "setMinimumHeight", min_height) &&
        padding(env, view, 16, 8);
}
static bool add_button(JNIEnv *env, jobject layout, jobject activity, const char *label, size_t i)
{
    jobject view = widget(env, "android/widget/Button", activity);
    bool primary = i == 9 || i == 0;
    bool ok = view && style_button(env, view, i, primary) && text(env, view, label) &&
        append(env, layout, view) && keep(env, &buttons[i], view);
    if (ok && primary) ok = int_property(env, view, "setBackgroundColor", (jint)0xff235e50);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
void zapp_native_ui_destroy(JNIEnv *env)
{
    for (size_t i = 0; i < sizeof(buttons) / sizeof(buttons[0]); ++i) {
        if (buttons[i]) (*env)->DeleteGlobalRef(env, buttons[i]);
        buttons[i] = NULL;
    }
    jobject *views[] = {&root, &status_view, &balance_view, &result_view, &notice_view, &details_view, &prompt_view, &invite_view, &camera_view, &connection_view, &transcript_view, &fleet_view, &receipt_view, &voice_view, &pair_view, &hosts_view, &sync_view};
    for (size_t i = 0; i < sizeof(views) / sizeof(views[0]); ++i) {
        if (*views[i]) (*env)->DeleteGlobalRef(env, *views[i]);
        *views[i] = NULL;
    }
    callback = NULL; pressed = -1; details_open = false; reply_state = ZAPP_REPLY_READY; last_receipt[0] = 0;
}
/* The main screen holds only the status, Talk and the conversation; everything else is under More.
 * Talk stays put above the conversation while status text changes. */
static bool node_widgets(JNIEnv *env, jobject layout, jobject activity, jobject prompt, jobject invite, jobject camera, jobject receipt, jobject scroll)
{
    (void)prompt; (void)invite; (void)camera; (void)receipt; (void)scroll;
    return !(!add_text(env, layout, activity, "", &status_view) ||
        !add_button(env, layout, activity, "Start node", 0) ||
        !add_text(env, layout, activity, "", &pair_view) ||
        !add_button(env, layout, activity, "Accept pairing", 12) ||
        !add_button(env, layout, activity, "Reject", 13) ||
        !add_button(env, layout, activity, "Talk", 9) ||
        !add_text(env, layout, activity, "Press Talk and ask anything.", &voice_view) ||
        !add_button(env, layout, activity, "Confirm", 10) ||
        !add_text(env, layout, activity, "", &notice_view) ||
        !add_text(env, layout, activity, "", &transcript_view) ||
        !add_button(env, layout, activity, "More", 8));
}
static bool chat_widgets(JNIEnv *env, jobject layout, jobject activity, jobject prompt, jobject invite, jobject camera, jobject receipt, jobject scroll)
{
    (void)invite; (void)camera; (void)receipt; (void)scroll;
    return !(!add_text(env, layout, activity, "Type a question", NULL) ||
        !append(env, layout, prompt) || !keep(env, &prompt_view, prompt) ||
        !add_button(env, layout, activity, "Send", 3) ||
        !add_text(env, layout, activity, "Not connected", &connection_view) ||
        !add_text(env, layout, activity, "Fleet", NULL) ||
        !add_text(env, layout, activity, "Ask by voice, or refresh to check every host.", &hosts_view) ||
        !add_button(env, layout, activity, "Refresh fleet", 14) ||
        !add_text(env, layout, activity, "Phone node", NULL) ||
        !add_text(env, layout, activity, "", &sync_view) ||
        !add_text(env, layout, activity, "Balance appears when your node is ready", &balance_view));
}
static bool detail_controls(JNIEnv *env, jobject layout, jobject activity)
{
    return add_button(env, layout, activity, "Stop node", 1) &&
        add_text(env, layout, activity, "Fleet invitation", NULL);
}
static bool fleet_widgets(JNIEnv *env, jobject layout, jobject activity, jobject prompt, jobject invite, jobject camera, jobject receipt, jobject scroll)
{
    (void)prompt; (void)invite; (void)camera; (void)receipt; (void)scroll;
    return !(!detail_controls(env, layout, activity) ||
        !add_button(env, layout, activity, "Scan invitation", 4) ||
        !append(env, layout, camera) || !keep(env, &camera_view, camera) ||
        !append(env, layout, invite) || !keep(env, &invite_view, invite) ||
        !add_button(env, layout, activity, "Review invitation", 5) ||
        !add_button(env, layout, activity, "Join fleet", 6) ||
        !add_text(env, layout, activity, "", &fleet_view));
}
static bool finish_widgets(JNIEnv *env, jobject layout, jobject activity, jobject receipt)
{
    return append(env, layout, receipt) && keep(env, &receipt_view, receipt) &&
        add_text(env, layout, activity, "", &result_view);
}
static bool orient_layout(JNIEnv *env, jobject layout)
{
    jclass cls = (*env)->GetObjectClass(env, layout);
    jmethodID method = cls ? (*env)->GetMethodID(env, cls, "setOrientation", "(I)V") : NULL;
    if (!clean(env) || !method) return false;
    (*env)->CallVoidMethod(env, layout, method, 1);
    return clean(env);
}
static bool set_visible(JNIEnv *env, jobject view, bool visible)
{
    jclass cls = (*env)->GetObjectClass(env, view);
    jmethodID set = cls ? (*env)->GetMethodID(env, cls, "setVisibility", "(I)V") : NULL;
    bool ok = clean(env) && set;
    if (ok) { (*env)->CallVoidMethod(env, view, set, visible ? 0 : 8); ok = clean(env); }
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return ok;
}
static bool show_root(JNIEnv *env, jobject activity, jobject scroll)
{
    jclass cls = (*env)->GetObjectClass(env, activity);
    jmethodID method = cls ? (*env)->GetMethodID(env, cls, "setContentView", "(Landroid/view/View;)V") : NULL;
    if (!clean(env) || !method) return false;
    (*env)->CallVoidMethod(env, activity, method, scroll);
    return clean(env);
}
static bool style_system_bars(JNIEnv *env, jobject activity)
{
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)clean(env); return false; }
    jobject window = object_property(env, activity, "getWindow", "()Landroid/view/Window;");
    jobject view = window ? object_property(env, window, "getDecorView", "()Landroid/view/View;") : NULL;
    bool ok = view && int_property(env, view, "setSystemUiVisibility", 0x2010);
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
static bool style_prompt(JNIEnv *env, jobject field)
{
    return typography(env, field, 16.0f, (jint)0xff262b2b) &&
           int_property(env, field, "setMinLines", 1) && int_property(env, field, "setMaxLines", 4);
}
static bool prepare_layouts(JNIEnv *env, jobject scroll, jobject layout,
                            jobject details, jobject prompt, jobject invite,
                            jobject camera, jobject receipt)
{
    return scroll && layout && prompt && invite && camera && receipt && details &&
           orient_layout(env, layout) && orient_layout(env, details) &&
           bool_property(env, scroll, "setFitsSystemWindows", true) &&
           int_property(env, scroll, "setBackgroundColor", (jint)0xfff7f5ef) &&
           padding(env, layout, 20, 20) && style_prompt(env, prompt) && style_prompt(env, invite) &&
           char_sequence(env, invite, "setHint", "Or paste an invitation");
}
static bool attach_details(JNIEnv *env, jobject details, jobject layout, jobject scroll)
{
    return set_visible(env, details, false) && append(env, layout, details) &&
           keep(env, &details_view, details) && append(env, scroll, layout) &&
           keep(env, &root, scroll);
}
static bool build_ui(JNIEnv *env, jobject activity)
{
    jobject scroll = widget(env, "android/widget/ScrollView", activity);
    jobject layout = widget(env, "android/widget/LinearLayout", activity);
    jobject details = widget(env, "android/widget/LinearLayout", activity);
    jobject prompt = widget(env, "android/widget/EditText", activity);
    jobject invite = widget(env, "android/widget/EditText", activity);
    jobject camera = widget(env, "android/widget/ImageView", activity);
    jobject receipt = widget(env, "android/widget/ImageView", activity);
    return prepare_layouts(env, scroll, layout, details, prompt, invite, camera, receipt) &&
        node_widgets(env, layout, activity, prompt, invite, camera, receipt, scroll) &&
        chat_widgets(env, details, activity, prompt, invite, camera, receipt, scroll) &&
        fleet_widgets(env, details, activity, prompt, invite, camera, receipt, scroll) &&
        finish_widgets(env, details, activity, receipt) &&
        attach_details(env, details, layout, scroll) && show_root(env, activity, scroll);
}
bool zapp_native_ui_create(JNIEnv *env, jobject activity, zapp_native_action action)
{
    if (!env || !activity || !action || root) return false;
    if ((*env)->PushLocalFrame(env, 32) != JNI_OK) { (void)clean(env); return false; }
    bool ok = load_density(env, activity) && load_identity(env, activity) &&
        style_system_bars(env, activity) && build_ui(env, activity);
    if (ok) callback = action;
    (void)clean(env);
    (*env)->PopLocalFrame(env, NULL);
    if (!ok) zapp_native_ui_destroy(env);
    return ok;
}
static void emit_utf8(char *out, size_t *used, uint32_t cp)
{
                if (cp < 0x80) out[(*used)++] = (char)cp;
                else if (cp < 0x800) { out[(*used)++] = (char)(0xc0 | (cp >> 6)); out[(*used)++] = (char)(0x80 | (cp & 63)); }
                else if (cp < 0x10000) { out[(*used)++] = (char)(0xe0 | (cp >> 12)); out[(*used)++] = (char)(0x80 | ((cp >> 6) & 63)); out[(*used)++] = (char)(0x80 | (cp & 63)); }
                else { out[(*used)++] = (char)(0xf0 | (cp >> 18)); out[(*used)++] = (char)(0x80 | ((cp >> 12) & 63)); out[(*used)++] = (char)(0x80 | ((cp >> 6) & 63)); out[(*used)++] = (char)(0x80 | (cp & 63)); }
}
static char *encode_prompt(const jchar *chars, jsize n)
{
    char *out = NULL;
    out = malloc((size_t)n * 3 + 1); size_t used = 0;
            if (out) for (jsize i = 0; i < n; ++i) {
                uint32_t cp = chars[i];
                if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < n && chars[i + 1] >= 0xdc00 && chars[i + 1] <= 0xdfff)
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (chars[++i] - 0xdc00);
                else if (!cp || (cp >= 0xd800 && cp <= 0xdfff)) { free(out); out = NULL; break; }
                emit_utf8(out, &used, cp);
            }
            if (out) out[used] = 0;
    return out;
}
static char *string_utf8(JNIEnv *env, jstring string)
{
    jsize n = (*env)->GetStringLength(env, string);
    const jchar *chars = (*env)->GetStringChars(env, string, NULL);
    char *out = NULL;
    if (clean(env) && chars && n <= 16000) out = encode_prompt(chars, n);
    if (chars) (*env)->ReleaseStringChars(env, string, chars);
    return out;
}
static char *prompt_utf8(JNIEnv *env, jobject field)
{
    jclass cls = (*env)->GetObjectClass(env, field);
    if (!clean(env) || !cls) return NULL;
    jmethodID get = (*env)->GetMethodID(env, cls, "getText", "()Landroid/text/Editable;");
    jobject editable = get ? (*env)->CallObjectMethod(env, field, get) : NULL;
    if (!clean(env) || !editable) { (*env)->DeleteLocalRef(env, cls); return NULL; }
    jclass edit_class = (*env)->GetObjectClass(env, editable);
    jmethodID to_string = edit_class ? (*env)->GetMethodID(env, edit_class, "toString", "()Ljava/lang/String;") : NULL;
    jstring string = to_string ? (*env)->CallObjectMethod(env, editable, to_string) : NULL;
    char *out = NULL;
    if (clean(env) && string) out = string_utf8(env, string);
    (void)clean(env);
    if (string) (*env)->DeleteLocalRef(env, string);
    if (edit_class) (*env)->DeleteLocalRef(env, edit_class);
    (*env)->DeleteLocalRef(env, editable); (*env)->DeleteLocalRef(env, cls);
    return out;
}
static bool hit(JNIEnv *env, jobject view, float x, float y)
{
    jclass cls = (*env)->GetObjectClass(env, view);
    if (!clean(env) || !cls) return false;
    jmethodID location = (*env)->GetMethodID(env, cls, "getLocationInWindow", "([I)V");
    jmethodID width = (*env)->GetMethodID(env, cls, "getWidth", "()I");
    jmethodID height = (*env)->GetMethodID(env, cls, "getHeight", "()I");
    jmethodID visible = (*env)->GetMethodID(env, cls, "isShown", "()Z");
    jintArray pos = (*env)->NewIntArray(env, 2); jint xy[2] = {0};
    bool ok = clean(env) && location && width && height && visible && pos;
    if (ok) {
        (*env)->CallVoidMethod(env, view, location, pos);
        (*env)->GetIntArrayRegion(env, pos, 0, 2, xy);
        jint w = (*env)->CallIntMethod(env, view, width), h = (*env)->CallIntMethod(env, view, height);
        jboolean shown = (*env)->CallBooleanMethod(env, view, visible);
        ok = clean(env) && shown && x >= xy[0] && y >= xy[1] && x < xy[0] + w && y < xy[1] + h;
    }
    if (pos) (*env)->DeleteLocalRef(env, pos);
    (*env)->DeleteLocalRef(env, cls); return ok;
}
static const char *voice_action(void)
{
    return voice_state == ZAPP_VOICE_READY ? "voice_start" :
        voice_state == ZAPP_VOICE_RECORDING ? "voice_finish" : "voice_cancel";
}
static bool fixed_action(int index, const char **action, const char **arg)
{
    *arg = "";
    switch (index) {
    case 3: *action = "chat_cancel"; return reply_state != ZAPP_REPLY_READY;
    case 9: *action = voice_action(); return true;
    case 10: *action = "voice_confirm"; return true;
    case 12: *action = "pair_accept"; return true;
    case 13: *action = "pair_reject"; return true;
    case 14: *action = "fleet_hosts"; *arg = "refresh"; return true;
    default: return false;
    }
}
static void text_action(JNIEnv *env, const char *action, jobject field)
{
    char *value = prompt_utf8(env, field);
    if (!value) return;
    callback(action, value);
    memory_cleanse(value, strlen(value)); free(value);
}
static void input_up(JNIEnv *env, float x, float y)
{
    int index = pressed; pressed = -1;
    if (index < 0 || !hit(env, buttons[index], x, y)) return;
    if (index == 8) {
        bool next = !details_open;
        if (set_visible(env, details_view, next)) { details_open = next; (void)text(env, buttons[8], next ? "Less" : "More"); }
        return;
    }
    const char *action, *arg;
    if (fixed_action(index, &action, &arg)) { callback(action, arg); return; }
    if (index >= (int)(sizeof(actions) / sizeof(*actions)) || !actions[index]) return;
    if (index == 3 || index == 5) { text_action(env, actions[index], index == 3 ? prompt_view : invite_view); return; }
    callback(actions[index], "");
}
void zapp_native_ui_input(JNIEnv *env, const AInputEvent *event)
{
    if (!callback || !event || AInputEvent_getType(event) != AINPUT_EVENT_TYPE_MOTION) return;
    int32_t action = AMotionEvent_getAction(event) & AMOTION_EVENT_ACTION_MASK;
    float x = AMotionEvent_getX(event, 0), y = AMotionEvent_getY(event, 0);
    if (action == AMOTION_EVENT_ACTION_DOWN) {
        pressed = -1; down_x = x; down_y = y;
        for (size_t i = 0; i < sizeof(buttons) / sizeof(buttons[0]); ++i)
            if (buttons[i] && hit(env, buttons[i], x, y)) { pressed = (int)i; break; }
    } else if (action == AMOTION_EVENT_ACTION_MOVE) {
        if (x - down_x > 20 || down_x - x > 20 || y - down_y > 20 || down_y - y > 20) pressed = -1;
    } else if (action == AMOTION_EVENT_ACTION_CANCEL) pressed = -1;
    else if (action == AMOTION_EVENT_ACTION_UP) input_up(env, x, y);
}
void zapp_native_ui_update(JNIEnv *env, const char *status, const char *output)
{
    if (voice_view && status) (void)text(env, voice_view, status);
    if (notice_view && output) { (void)text(env, notice_view, output); (void)set_visible(env, notice_view, true); }
}

static jobject decode_bitmap(JNIEnv *env, const unsigned char *bmp, size_t len)
{
    jclass factory = (*env)->FindClass(env, "android/graphics/BitmapFactory");
    jmethodID decode = factory ? (*env)->GetStaticMethodID(env, factory, "decodeByteArray", "([BII)Landroid/graphics/Bitmap;") : NULL;
    jbyteArray data = bmp && len ? (*env)->NewByteArray(env, (jsize)len) : NULL;
    if (data) (*env)->SetByteArrayRegion(env, data, 0, (jsize)len, (const jbyte *)bmp);
    jobject bitmap = clean(env) && decode && data ? (*env)->CallStaticObjectMethod(env, factory, decode, data, 0, (jint)len) : NULL;
    return bitmap;
}
static bool set_bitmap(JNIEnv *env, jobject view, const unsigned char *bmp, size_t len)
{
    if (!view || len > 1024 * 1024) return false;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)clean(env); return false; }
    jobject bitmap = decode_bitmap(env, bmp, len);
    jclass image = (*env)->GetObjectClass(env, view);
    jmethodID set = image ? (*env)->GetMethodID(env, image, "setImageBitmap", "(Landroid/graphics/Bitmap;)V") : NULL;
    bool ok = clean(env) && set && (!bmp || bitmap);
    if (ok) { (*env)->CallVoidMethod(env, view, set, bitmap); ok = clean(env); }
    (void)clean(env); (*env)->PopLocalFrame(env, NULL); return ok;
}

void zapp_native_ui_preview(JNIEnv *env, const unsigned char *bmp, size_t len)
{ (void)set_bitmap(env, camera_view, bmp, len); }

static void receipt_qr(JNIEnv *env, const char *value)
{
    if (!strcmp(last_receipt, value)) return;
    last_receipt[0] = 0;
    if (!*value) { (void)set_bitmap(env, receipt_view, NULL, 0); return; }
    size_t size = 0;
    unsigned char *bmp = zapp_fleet_qr_bmp(value, &size);
    bool shown = bmp && set_bitmap(env, receipt_view, bmp, size);
    free(bmp);
    if (shown && strlen(value) < sizeof(last_receipt)) memcpy(last_receipt, value, strlen(value) + 1);
    else (void)set_bitmap(env, receipt_view, NULL, 0);
}
static const char *talk_label(enum zapp_voice_state state)
{
    return state == ZAPP_VOICE_READY ? "Talk" : state == ZAPP_VOICE_RECORDING ? "Done talking" :
        state == ZAPP_VOICE_PLAYING ? "Stop speaking" : "Cancel";
}
static void render_voice(JNIEnv *env, const struct zapp_view *view)
{
    if (buttons[9]) (void)text(env, buttons[9], talk_label(voice_state));
    if (voice_view) (void)text(env, voice_view, view->voice_status[0] ? view->voice_status :
        "Press Talk and ask anything.");
    if (buttons[10]) {
        (void)text(env, buttons[10], !strcmp(view->voice_proposal, "node_start") ? "Confirm start" : "Confirm stop");
        (void)set_visible(env, buttons[10], view->voice_proposal[0] && !view->busy);
    }
}
static void render_node(JNIEnv *env, const struct zapp_view *view)
{
    const char *send_label = reply_state == ZAPP_REPLY_WAITING ? "Stop reply" :
        reply_state == ZAPP_REPLY_CANCELLING ? "Stopping…" : "Send";
    if (buttons[3]) (void)text(env, buttons[3], send_label);
    char status[1100];
    snprintf(status, sizeof(status), "%s%s", view->sync_status[0] ? view->sync_status : "Sync status unknown",
             view->busy ? "\nWorking…" : "");
    (void)text(env, sync_view, voice_preview ? "The preview app does not run a node." : status);
    (void)set_visible(env, balance_view, !voice_preview);
    char balance[600];
    snprintf(balance, sizeof(balance), "%s%s", view->balance_stale ? "Last known:\n" : "",
             view->balance[0] ? view->balance : "Balance appears when your node is ready");
    (void)text(env, balance_view, balance);
    (void)text(env, connection_view, view->connection[0] ? view->connection : "Connect a laptop to use chat.");
    (void)text(env, transcript_view, view->transcript);
    (void)set_visible(env, transcript_view, view->transcript[0] != 0);
}
/* Two lines at the top: the phone node and, while a laptop host is paired, the fleet headline. */
static void render_status(JNIEnv *env, const struct zapp_view *view)
{
    char fleet[160], status[320];
    zapp_fleet_line(view->fleet_status, view->fleet_stale, view->fleet_paired, fleet, sizeof(fleet));
    snprintf(status, sizeof(status), "%s%s%s", voice_preview ?
             "Preview · separate from your main node" : view->node_line, fleet[0] ? "\n" : "", fleet);
    (void)text(env, status_view, status);
    bool running = view->node_running || view->node_process_running;
    bool shown = !voice_preview && !view->busy;
    if (buttons[0]) (void)set_visible(env, buttons[0], shown && !running);
    /* Stop node also clears a saved Start node choice when that node has exited on its own. */
    if (buttons[1]) (void)set_visible(env, buttons[1], shown && (running || view->node_wanted));
}
static void render_fleet(JNIEnv *env, const struct zapp_view *view)
{
    char fleet[10272], pairing[160];
    /* The headline is already at the top of the screen; More lists the hosts under it. */
    const char *rows = strchr(view->fleet_status, '\n');
    if (rows) rows += strspn(rows, "\n");
    if (view->fleet_status[0]) {
        snprintf(fleet, sizeof(fleet), "%s%s", view->fleet_stale ? "No current fleet report. Last report:\n\n" : "",
                 view->fleet_stale || !rows ? view->fleet_status : rows);
        (void)text(env, hosts_view, fleet);
    }
    snprintf(fleet, sizeof(fleet), "%s%s%s", view->fleet_preview,
             view->fleet_receipt[0] ? "\nReceipt: " : "", view->fleet_receipt);
    snprintf(pairing, sizeof(pairing), "Your laptop offers private voice and fleet control. "
             "Accept only if the laptop shows code %s.", view->pair_code);
    (void)text(env, pair_view, pairing);
    (void)set_visible(env, pair_view, view->pair_offer[0] != 0);
    for (int i = 12; i <= 13; ++i) if (buttons[i]) (void)set_visible(env, buttons[i], view->pair_offer[0] && !view->busy);
    (void)text(env, fleet_view, fleet);
    (void)text(env, notice_view, view->notice);
    (void)set_visible(env, notice_view, view->notice[0] != 0);
    (void)text(env, result_view, view->result);
}
void zapp_native_ui_render(JNIEnv *env, const struct zapp_view *view)
{
    if (!env || !view) return;
    reply_state = view->reply_state;
    voice_state = view->voice_state;
    render_voice(env, view);
    render_status(env, view);
    render_node(env, view);
    render_fleet(env, view);
    receipt_qr(env, view->fleet_receipt);
}
