# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.22)
project(z23android LANGUAGES C)

if(NOT ANDROID OR NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "z23android requires the Android NDK arm64-v8a toolchain")
endif()
get_filename_component(Z23_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(Z23_ANDROID_API "35" CACHE STRING "API used to build the bundled crypto archive")
set(Z23_CRYPTO "${Z23_ROOT}/vendor/cross/aarch64-linux-android${Z23_ANDROID_API}/lib/libcrypto.a" CACHE FILEPATH "Pinned Android crypto archive")
if(NOT EXISTS "${Z23_CRYPTO}")
    message(FATAL_ERROR "Build the pinned Android vendor archives before z23android")
endif()
set(Z23_QUIRC_DIR "" CACHE PATH "Prepared quirc sources from make prepare-quirc")
if(NOT EXISTS "${Z23_QUIRC_DIR}/quirc.c")
    message(FATAL_ERROR "Run make apk to prepare the pinned quirc sources")
endif()

add_library(z23android SHARED
    android_main.c node_service.c node_watch.c camera.c native_ui.c controller.c conversation.c bridge_client.c operations.c fleet.c
    audio.c speech_client.c voice.c hosts.c pairing.c
    "${Z23_ROOT}/platform/modules/sha3/src/sha3.c"
    "${Z23_ROOT}/contexts/commons/packages/zutf8/src/zutf8.c"
    "${Z23_ROOT}/vendor/qrcodegen/qrcodegen.c"
    "${Z23_QUIRC_DIR}/quirc.c" "${Z23_QUIRC_DIR}/decode.c"
    "${Z23_QUIRC_DIR}/identify.c" "${Z23_QUIRC_DIR}/version_db.c"
    "${Z23_ROOT}/platform/modules/json/src/json.c"
    "${Z23_ROOT}/platform/modules/base/src/safe_alloc.c"
    "${Z23_ROOT}/platform/modules/base/src/cleanse.c")
target_include_directories(z23android PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${Z23_ROOT}/contexts/commons/packages/zutf8/include"
    "${Z23_QUIRC_DIR}"
    "${Z23_ROOT}/vendor/qrcodegen"
    "${Z23_ROOT}/platform/modules/json/include"
    "${Z23_ROOT}/platform/modules/base/include"
    "${Z23_ROOT}/platform/modules/sha3/include"
    "${Z23_ROOT}/vendor/cross/aarch64-linux-android${Z23_ANDROID_API}/include"
    "${Z23_ROOT}/vendor/include")
target_compile_options(z23android PRIVATE -std=c23 -Wall -Wextra -Werror -pedantic
    -fstack-protector-strong -fvisibility=hidden -ffunction-sections -fdata-sections)
target_compile_definitions(z23android PRIVATE _POSIX_C_SOURCE=200809L)
target_link_options(z23android PRIVATE -Wl,--no-undefined -Wl,--gc-sections
    -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,max-page-size=16384)
target_link_libraries(z23android PRIVATE "${Z23_CRYPTO}" android log dl m camera2ndk mediandk aaudio)
