/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "game_view.h"
#include "game.h"
#include "jni_util.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define PNG_CAP 1048576u
static struct { jobject root, image, status; uint64_t version; } view;
static bool layout_views(JNIEnv *env, jobject root, jobject image, jobject status, jobject help)
{
    return zj_text(env, help, "Left: fly. Right: fire. Top right: boost. Back: stop.") &&
        zj_typography(env, help, 16, (jint)0xffffffffu) && zj_typography(env, status, 16, (jint)0xffffffffu) &&
        zj_margins(env, image, -1, 0, 1.0f, 0, 0, 0, 0) && zj_append(env, root, image) &&
        zj_append(env, root, status) && zj_append(env, root, help);
}
bool zapp_game_view_create(JNIEnv *env, jobject activity, jobject root)
{
    jobject image = zj_widget(env, "android/widget/ImageView", activity);
    jobject status = zj_widget(env, "android/widget/TextView", activity);
    jobject help = zj_widget(env, "android/widget/TextView", activity);
    bool ok = image && status && help && layout_views(env, root, image, status, help) &&
        zj_keep(env, &view.root, root) && zj_keep(env, &view.image, image) && zj_keep(env, &view.status, status);
    if (image) (*env)->DeleteLocalRef(env, image);
    if (status) (*env)->DeleteLocalRef(env, status);
    if (help) (*env)->DeleteLocalRef(env, help);
    return ok;
}
void zapp_game_view_render(JNIEnv *env)
{
    if (!view.image) return;
    unsigned char *png = malloc(PNG_CAP);
    if (png) {
        size_t n = zapp_game_frame(png, PNG_CAP, &view.version);
        if (n) (void)zj_bitmap(env, view.image, png, n);
        free(png);
    }
    char status[160]; zapp_game_status(status, sizeof(status));
    (void)zj_text(env, view.status, status);
}
void zapp_game_view_clear(JNIEnv *env)
{
    if (view.image) (void)zj_bitmap(env, view.image, NULL, 0);
}
static bool image_geometry(JNIEnv *env, jint *width, jint *height, jint origin[2])
{
    jmethodID w = zj_method(env, view.image, "getWidth", "()I"), h = zj_method(env, view.image, "getHeight", "()I");
    jmethodID loc = zj_method(env, view.image, "getLocationInWindow", "([I)V");
    jintArray coords = (*env)->NewIntArray(env, 2);
    if (!w || !h || !loc || !coords) { (void)zj_clean(env); if (coords) (*env)->DeleteLocalRef(env, coords); return false; }
    *width = (*env)->CallIntMethod(env, view.image, w); *height = (*env)->CallIntMethod(env, view.image, h);
    (*env)->CallVoidMethod(env, view.image, loc, coords);
    (*env)->GetIntArrayRegion(env, coords, 0, 2, origin);
    (*env)->DeleteLocalRef(env, coords);
    return zj_clean(env) && *width > 0 && *height > 0;
}
void zapp_game_view_touch(JNIEnv *env, const AInputEvent *event)
{
    if (!view.root || !event) return;
    int action = AMotionEvent_getAction(event), kind = action & AMOTION_EVENT_ACTION_MASK;
    if (kind == AMOTION_EVENT_ACTION_CANCEL || kind == AMOTION_EVENT_ACTION_UP) {
        zapp_game_controls(0, 0, false, false); return;
    }
    jint width = 0, height = 0, origin[2] = {0};
    if (!image_geometry(env, &width, &height, origin)) { zapp_game_controls(0, 0, false, false); return; }
    float x = 0, y = 0; bool fire = false, boost = false;
    size_t count = AMotionEvent_getPointerCount(event);
    size_t lifted = kind == AMOTION_EVENT_ACTION_POINTER_UP ? (size_t)((action & AMOTION_EVENT_ACTION_POINTER_INDEX_MASK) >> AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT) : count;
    for (size_t i = 0; i < count; ++i) {
        if (i == lifted) continue;
        float px = (AMotionEvent_getX(event, i) - (float)origin[0]) / (float)width;
        float py = (AMotionEvent_getY(event, i) - (float)origin[1]) / (float)height;
        if (px < 0 || px > 1 || py < 0 || py > 1) continue;
        if (px < 0.5f) { x = (px - 0.25f) * 4.0f; y = (py - 0.5f) * 2.0f; }
        else if (py < 0.35f) boost = true;
        else fire = true;
    }
    zapp_game_controls(x, y, fire, boost);
}
void zapp_game_view_destroy(JNIEnv *env)
{
    if (view.root) (*env)->DeleteGlobalRef(env, view.root);
    if (view.image) (*env)->DeleteGlobalRef(env, view.image);
    if (view.status) (*env)->DeleteGlobalRef(env, view.status);
    view = (typeof(view)){0};
}
