# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
cmake_minimum_required(VERSION 3.21)
project(zcl_ledger C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(ledger_hid STATIC src/ledger_hid.c src/ledger_probe.c)
target_include_directories(ledger_hid PUBLIC include)
target_compile_options(ledger_hid PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(zcl-ledger src/main.c)
target_link_libraries(zcl-ledger PRIVATE ledger_hid)
target_compile_options(zcl-ledger PRIVATE -Wall -Wextra -Werror -pedantic)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    foreach(target ledger_hid zcl-ledger)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PUBLIC -fsanitize=address,undefined)
    endforeach()
endif()

enable_testing()
add_executable(test-ledger-hid tests/test_ledger_hid.c)
target_link_libraries(test-ledger-hid PRIVATE ledger_hid)
target_compile_options(test-ledger-hid PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-ledger-hid PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-ledger-hid PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME ledger-hid COMMAND test-ledger-hid)
