# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
cmake_minimum_required(VERSION 3.21)
project(zcl_ledger C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(ledger_hid STATIC src/ledger_hid.c src/ledger_probe.c)
target_include_directories(ledger_hid PUBLIC include)
target_compile_options(ledger_hid PRIVATE -Wall -Wextra -Werror -pedantic)

find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)
add_library(zcl_address STATIC src/zcl_address.c)
target_include_directories(zcl_address PUBLIC include)
target_link_libraries(zcl_address PUBLIC OpenSSL::Crypto)
target_compile_options(zcl_address PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(zcl_tx_review STATIC src/zcl_tx_review.c)
target_include_directories(zcl_tx_review PUBLIC include)
target_compile_options(zcl_tx_review PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(zcl_zip243 STATIC src/zcl_zip243.c)
target_include_directories(zcl_zip243 PUBLIC include)
target_link_libraries(zcl_zip243 PUBLIC zcl_tx_review)
target_compile_options(zcl_zip243 PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(zcl_zip243_host_hash STATIC
    src/zcl_zip243_host.c
    ../../core/modules/crypto/src/blake2b.c
    ../../platform/modules/base/src/log_level.c)
target_include_directories(zcl_zip243_host_hash PUBLIC
    include
    ../../core/modules/crypto/include
    ../../platform/modules/util/include
    ../../platform/modules/base/include)
target_compile_definitions(zcl_zip243_host_hash PRIVATE _POSIX_C_SOURCE=200809L)
target_compile_options(zcl_zip243_host_hash PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_review_protocol STATIC src/blue_review_protocol.c)
target_include_directories(blue_review_protocol PUBLIC include)
target_link_libraries(blue_review_protocol PUBLIC zcl_tx_review zcl_zip243)
target_compile_options(blue_review_protocol PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(zcl-tx-review src/tx_review_cli.c)
target_link_libraries(zcl-tx-review PRIVATE zcl_tx_review zcl_zip243_host_hash blue_review_protocol ledger_hid OpenSSL::Crypto)
target_compile_options(zcl-tx-review PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(zcl-ledger src/main.c)
target_link_libraries(zcl-ledger PRIVATE ledger_hid zcl_address)
target_compile_options(zcl-ledger PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_secure STATIC src/blue_secure.c)
target_include_directories(blue_secure PUBLIC include)
target_link_libraries(blue_secure PUBLIC OpenSSL::Crypto)
target_compile_options(blue_secure PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_ca STATIC src/blue_ca.c)
target_include_directories(blue_ca PUBLIC include)
target_link_libraries(blue_ca PUBLIC blue_secure)
target_compile_options(blue_ca PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(zcl-blue-ca src/blue_ca_cli.c)
target_link_libraries(zcl-blue-ca PRIVATE blue_ca)
target_compile_options(zcl-blue-ca PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(zcl-blue-install src/blue_install.c)
target_link_libraries(zcl-blue-install PRIVATE ledger_hid blue_secure blue_ca)
target_compile_options(zcl-blue-install PRIVATE -Wall -Wextra -Werror -pedantic)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    foreach(target ledger_hid zcl_address zcl_tx_review zcl_zip243 zcl_zip243_host_hash blue_review_protocol zcl-tx-review zcl-ledger blue_secure blue_ca zcl-blue-ca zcl-blue-install)
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

add_executable(test-blue-secure tests/test_blue_secure.c)
target_link_libraries(test-blue-secure PRIVATE blue_secure)
target_compile_options(test-blue-secure PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-secure PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-secure PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-secure COMMAND test-blue-secure)

add_executable(test-blue-ca tests/test_blue_ca.c)
target_link_libraries(test-blue-ca PRIVATE blue_ca)
target_compile_options(test-blue-ca PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-ca PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-ca PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-ca COMMAND test-blue-ca)

add_executable(test-zcl-address tests/test_zcl_address.c)
target_link_libraries(test-zcl-address PRIVATE zcl_address)
target_compile_options(test-zcl-address PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-zcl-address PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-zcl-address PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME zcl-address COMMAND test-zcl-address)

add_executable(test-zcl-tx-review tests/test_zcl_tx_review.c)
target_link_libraries(test-zcl-tx-review PRIVATE zcl_tx_review)
target_compile_options(test-zcl-tx-review PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-zcl-tx-review PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-zcl-tx-review PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME zcl-tx-review COMMAND test-zcl-tx-review)

add_executable(test-zcl-zip243 tests/test_zcl_zip243.c)
target_link_libraries(test-zcl-zip243 PRIVATE zcl_zip243 zcl_zip243_host_hash)
target_compile_options(test-zcl-zip243 PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-zcl-zip243 PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-zcl-zip243 PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME zcl-zip243 COMMAND test-zcl-zip243
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/zip243-vector1.hex)

add_executable(test-blue-review-protocol tests/test_blue_review_protocol.c)
target_link_libraries(test-blue-review-protocol PRIVATE blue_review_protocol zcl_zip243_host_hash OpenSSL::Crypto)
target_compile_options(test-blue-review-protocol PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-review-protocol PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-review-protocol PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-review-protocol COMMAND test-blue-review-protocol)
