/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Syntax-only stand-in for the raylib 6.0 / raymath / rlgl API used by
 * tools/arena_view.c. Linked builds use the real headers from pkg-config.
 * This stub is not a runtime and is not measured.
 */
#ifndef ARENA_VIEW_RAYLIB_STUB_H
#define ARENA_VIEW_RAYLIB_STUB_H

#include <stdbool.h>

typedef struct Vector2 {
    float x, y;
} Vector2;
typedef struct Vector3 {
    float x, y, z;
} Vector3;
typedef struct Color {
    unsigned char r, g, b, a;
} Color;
typedef struct Rectangle {
    float x, y, width, height;
} Rectangle;
typedef struct Matrix {
    float m0, m4, m8, m12;
    float m1, m5, m9, m13;
    float m2, m6, m10, m14;
    float m3, m7, m11, m15;
} Matrix;
typedef struct Camera3D {
    Vector3 position;
    Vector3 target;
    Vector3 up;
    float fovy;
    int projection;
} Camera3D;
typedef struct Image {
    void *data;
    int width;
    int height;
    int mipmaps;
    int format;
} Image;
typedef struct Texture {
    unsigned int id;
    int width;
    int height;
    int mipmaps;
    int format;
} Texture2D;
typedef struct GlyphInfo {
    int value;
    int offsetX;
    int offsetY;
    int advanceX;
    Image image;
} GlyphInfo;
typedef struct Font {
    int baseSize;
    int glyphCount;
    int glyphPadding;
    Texture2D texture;
    Rectangle *recs;
    GlyphInfo *glyphs;
} Font;
typedef struct float16 {
    float v[16];
} float16;

#ifndef PI
#define PI 3.14159265358979323846f
#endif
#ifndef DEG2RAD
#define DEG2RAD (PI / 180.0f)
#endif
#define WHITE ((Color){ 255, 255, 255, 255 })
#define BLACK ((Color){ 0, 0, 0, 255 })

#define FLAG_MSAA_4X_HINT 0x00000020
#define FLAG_WINDOW_HIDDEN 0x00000080
#define CAMERA_PERSPECTIVE 0
#define PIXELFORMAT_UNCOMPRESSED_R8G8B8A8 7
#define MOUSE_BUTTON_LEFT 0
#define KEY_TAB 258
#define KEY_C 67
#define KEY_SPACE 32
#define KEY_F 70
#define KEY_R 82
#define KEY_HOME 268
#define KEY_END 269
#define KEY_RIGHT 262
#define KEY_LEFT 263
#define KEY_PAGE_UP 266
#define KEY_PAGE_DOWN 267
#define KEY_EQUAL 61
#define KEY_KP_ADD 334
#define KEY_MINUS 45
#define KEY_KP_SUBTRACT 333

#define MatrixToFloat(mat) (MatrixToFloatV(mat).v)

void SetConfigFlags(unsigned int flags);
void InitWindow(int width, int height, const char *title);
bool IsWindowReady(void);
void CloseWindow(void);
void SetTargetFPS(int fps);
bool WindowShouldClose(void);
float GetFrameTime(void);
int GetScreenWidth(void);
int GetScreenHeight(void);
void BeginDrawing(void);
void EndDrawing(void);
void BeginMode3D(Camera3D camera);
void EndMode3D(void);
void ClearBackground(Color color);
void DrawSphere(Vector3 centerPos, float radius, Color color);
void DrawPlane(Vector3 centerPos, Vector2 size, Color color);
void DrawGrid(int slices, float spacing);
void DrawCube(Vector3 position, float width, float height, float length,
              Color color);
void DrawCubeWires(Vector3 position, float width, float height, float length,
                   Color color);
void DrawCylinder(Vector3 position, float radiusTop, float radiusBottom,
                  float height, int slices, Color color);
void DrawLine3D(Vector3 startPos, Vector3 endPos, Color color);
void DrawText(const char *text, int posX, int posY, int fontSize, Color color);
void DrawTextEx(Font font, const char *text, Vector2 position, float fontSize,
                float spacing, Color tint);
int MeasureText(const char *text, int fontSize);
Vector2 MeasureTextEx(Font font, const char *text, float fontSize,
                      float spacing);
const char *TextFormat(const char *text, ...);
void DrawCircle(int centerX, int centerY, float radius, Color color);
void DrawCircleLines(int centerX, int centerY, float radius, Color color);
void DrawLine(int startPosX, int startPosY, int endPosX, int endPosY,
              Color color);
void DrawRectangle(int posX, int posY, int width, int height, Color color);
void DrawRectangleLines(int posX, int posY, int width, int height, Color color);
void DrawRectangleLinesEx(Rectangle rec, float lineThick, Color color);
void DrawTexture(Texture2D texture, int posX, int posY, Color tint);
bool IsMouseButtonDown(int button);
Vector2 GetMouseDelta(void);
float GetMouseWheelMove(void);
int GetRandomValue(int min, int max);
bool IsKeyPressed(int key);
Image GenImageColor(int width, int height, Color color);
Texture2D LoadTextureFromImage(Image image);
void UnloadImage(Image image);
void UpdateTexture(Texture2D texture, const void *pixels);
bool IsTextureValid(Texture2D texture);
void UnloadTexture(Texture2D texture);
bool ExportImage(Image image, const char *fileName);
Font LoadFontFromMemory(const char *fileType, const unsigned char *fileData,
                        int dataSize, int fontSize, int *codepoints,
                        int codepointCount);
bool IsFontValid(Font font);
void UnloadFont(Font font);
void MemFree(void *ptr);

Vector3 Vector3Normalize(Vector3 v);
Vector3 Vector3CrossProduct(Vector3 v1, Vector3 v2);
float Vector3Length(Vector3 v);
Vector3 Vector3Add(Vector3 v1, Vector3 v2);
Vector3 Vector3Scale(Vector3 v, float scale);
Vector3 Vector3Subtract(Vector3 v1, Vector3 v2);
Vector3 Vector3Lerp(Vector3 v1, Vector3 v2, float amount);
float Vector3Distance(Vector3 v1, Vector3 v2);
float Clamp(float value, float min, float max);
float16 MatrixToFloatV(Matrix mat);

void rlPushMatrix(void);
void rlPopMatrix(void);
void rlMultMatrixf(const float *matf);
void rlDrawRenderBatchActive(void);
unsigned char *rlReadScreenPixels(int width, int height);

#endif /* ARENA_VIEW_RAYLIB_STUB_H */
