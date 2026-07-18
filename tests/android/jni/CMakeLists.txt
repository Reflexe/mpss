# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# libmpss_tests_jni.so: the mpss gtest suite + a JNI entry point, statically
# linked into one .so so the process has a single OpenSSL instance. Configure
# with the same Android + vcpkg toolchain as mpss, plus -Dmpss_ROOT=<install>.
cmake_minimum_required(VERSION 3.25)
project(mpss_tests_jni LANGUAGES CXX)

if(DEFINED MPSS_ROOT AND NOT DEFINED mpss_ROOT)
    set(mpss_ROOT "${MPSS_ROOT}")
endif()

find_package(mpss REQUIRED)
find_package(GTest CONFIG REQUIRED)

get_filename_component(mpss_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)

add_library(mpss_tests_jni SHARED
    # mpss_openssl_tests.cpp (provider-internal unit tests) is omitted on purpose;
    # desktop CI covers it, and the emulator's job is the Keystore backend.
    "${mpss_REPO_ROOT}/tests/mpss_tests.cpp"
    "${mpss_REPO_ROOT}/tests/mpss_openssl_e2e_test.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/jni_test_runner.cpp"
)

target_compile_features(mpss_tests_jni PRIVATE cxx_std_20)
# Repo root resolves #include "tests/..."; mpss and OpenSSL headers come from the package.
target_include_directories(mpss_tests_jni PRIVATE "${mpss_REPO_ROOT}")
target_link_libraries(mpss_tests_jni PRIVATE mpss::mpss_openssl_static GTest::gtest log)

# JNI_OnLoad is referenced only by the runtime; force-keep it so it stays exported.
target_link_options(mpss_tests_jni PRIVATE "-Wl,-u,JNI_OnLoad")
