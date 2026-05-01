# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Build XCFrameworks for iOS (device + simulator).
#
# Usage (from project root):
#   cmake -P cmake/ios_xcframework.cmake
#   cmake -DBUILD_MPSS_OPENSSL=ON -P cmake/ios_xcframework.cmake
#   cmake -DBUILD_TYPE=Debug -DOUTPUT_DIR=./out -P cmake/ios_xcframework.cmake
#
# Options (pass with -D):
#   BUILD_TYPE     Build configuration: Release (default) or Debug.
#   BUILD_MPSS_OPENSSL  Build the OpenSSL provider XCFramework. Default: ON.
#   OUTPUT_DIR     Where to place the .xcframework bundles. Default: project root.
#   WORK_DIR       Directory for intermediate build/install files. Default: out/ios-xcframework.
#
# Scope and design notes:
#
# 1. iOS-only by design: produces arm64 slices for `iphoneos` (device) and
#    `iphonesimulator` (Apple Silicon Mac sim host). Does not cover x86_64
#    simulator (Intel Mac hosts), macOS native, Mac Catalyst, visionOS, etc.
#
# 2. Static-library XCFrameworks: the inner artifacts are .a archives, not
#    .framework bundles. Consequence: none of the dylib/framework runtime
#    machinery (LC_ID_DYLIB, LC_LOAD_DYLIB, LC_RPATH, install names) applies
#    to what we ship here -- static archives carry only object code plus a
#    LC_BUILD_VERSION per object identifying the platform slice. The
#    consumer's link step pulls our .o files into their final binary.
#
# 3. OpenSSL is not embedded: libmpss_openssl_static.a defines only its own
#    _OSSL_provider_init entry point; all _EVP_*/_BIO_*/_OSSL_*/_X509_*/etc.
#    references are left undefined for the consumer's link to resolve against
#    their own iOS-built OpenSSL. This is why the same vcpkg triplet header
#    path can serve both the device and simulator builds below: only headers
#    are consulted at our compile time, and OpenSSL's public headers are
#    SDK-agnostic. No iPhoneOS-flagged code leaks into the simulator slice.

cmake_minimum_required(VERSION 3.25)

# Defaults.
if(NOT DEFINED BUILD_TYPE)
    set(BUILD_TYPE Release)
endif()
if(NOT BUILD_TYPE STREQUAL "Release" AND NOT BUILD_TYPE STREQUAL "Debug")
    message(FATAL_ERROR "BUILD_TYPE must be 'Release' or 'Debug' (got '${BUILD_TYPE}').")
endif()
if(NOT DEFINED BUILD_MPSS_OPENSSL)
    set(BUILD_MPSS_OPENSSL ON)
endif()

# When building the OpenSSL provider, vcpkg must be available so the
# iOS-targeted OpenSSL headers and link target come from the right SDK.
# Without VCPKG_ROOT, CMake would silently fall back to system OpenSSL
# (Homebrew, /usr/lib) which is not iOS-compatible and fails late at
# compile or link time with confusing errors.
if(BUILD_MPSS_OPENSSL AND NOT DEFINED ENV{VCPKG_ROOT})
    message(FATAL_ERROR
        "BUILD_MPSS_OPENSSL=ON requires the VCPKG_ROOT environment variable "
        "to be set so an iOS-targeted OpenSSL can be located. Either set "
        "VCPKG_ROOT or pass -DBUILD_MPSS_OPENSSL=OFF.")
endif()

# Source directory is the parent of the cmake/ directory containing this script.
get_filename_component(SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

if(NOT DEFINED OUTPUT_DIR)
    set(OUTPUT_DIR "${SOURCE_DIR}")
endif()
get_filename_component(OUTPUT_DIR "${OUTPUT_DIR}" ABSOLUTE)

# Extract version from CMakeLists.txt for display.
file(READ "${SOURCE_DIR}/CMakeLists.txt" _cmakelists_content)
string(REGEX MATCH "project\\(mpss VERSION ([0-9.]+)" _match "${_cmakelists_content}")

message(STATUS "MPSS version: ${CMAKE_MATCH_1}")
message(STATUS "Build type: ${BUILD_TYPE}")
message(STATUS "Build OpenSSL provider: ${BUILD_MPSS_OPENSSL}")
message(STATUS "Output: ${OUTPUT_DIR}")

# Working directories (all under WORK_DIR to keep the project root clean).
if(NOT DEFINED WORK_DIR)
    set(WORK_DIR "${SOURCE_DIR}/out/ios-xcframework")
endif()
get_filename_component(WORK_DIR "${WORK_DIR}" ABSOLUTE)
set(BUILD_DEVICE "${WORK_DIR}/build-device")
set(BUILD_SIMULATOR "${WORK_DIR}/build-simulator")
set(INSTALL_DEVICE "${WORK_DIR}/install-device")
set(INSTALL_SIMULATOR "${WORK_DIR}/install-simulator")
set(XCF_STAGING "${WORK_DIR}/staging")

# Common CMake arguments.
set(COMMON_ARGS
    -S "${SOURCE_DIR}"
    -GXcode
    -DCMAKE_SYSTEM_NAME=iOS
    -DCMAKE_OSX_ARCHITECTURES=arm64
    # Static for iOS: App Store policy disallows dlopen of arbitrary user
    # code, so the OpenSSL provider must be linked into the consumer app at
    # build time and registered via OSSL_PROVIDER_add_builtin() rather than
    # OSSL_PROVIDER_load() of a dynamic .dylib.
    -DMPSS_BUILD_MPSS_CORE_STATIC=ON
    -DMPSS_BUILD_MPSS_OPENSSL_STATIC=${BUILD_MPSS_OPENSSL}
    # YubiKey is unsupported on iOS and the libykpiv vcpkg port has no iOS
    # triplet. Force it off here so a stray cache or environment variable
    # cannot accidentally enable it.
    -DMPSS_BACKEND_YUBIKEY=OFF
)
if(DEFINED ENV{VCPKG_ROOT})
    list(APPEND COMMON_ARGS
        "-DCMAKE_TOOLCHAIN_FILE=$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
endif()

# --- Configure ---

message(STATUS "Configuring for iOS device...")
execute_process(
    COMMAND ${CMAKE_COMMAND}
        ${COMMON_ARGS}
        -B "${BUILD_DEVICE}"
        -DCMAKE_OSX_SYSROOT=iphoneos
    RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Failed to configure for iOS device.")
endif()

message(STATUS "Configuring for iOS simulator...")
execute_process(
    COMMAND ${CMAKE_COMMAND}
        ${COMMON_ARGS}
        -B "${BUILD_SIMULATOR}"
        -DCMAKE_OSX_SYSROOT=iphonesimulator
    RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Failed to configure for iOS simulator.")
endif()

# --- Build ---

message(STATUS "Building for iOS device...")
execute_process(
    COMMAND ${CMAKE_COMMAND} --build "${BUILD_DEVICE}" --config ${BUILD_TYPE} -j
    RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Failed to build for iOS device.")
endif()

message(STATUS "Building for iOS simulator...")
execute_process(
    COMMAND ${CMAKE_COMMAND} --build "${BUILD_SIMULATOR}" --config ${BUILD_TYPE} -j
    RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Failed to build for iOS simulator.")
endif()

# --- Install ---

message(STATUS "Installing device build...")
execute_process(
    COMMAND ${CMAKE_COMMAND}
        --install "${BUILD_DEVICE}" --config ${BUILD_TYPE} --prefix "${INSTALL_DEVICE}"
    RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Failed to install device build.")
endif()

message(STATUS "Installing simulator build...")
execute_process(
    COMMAND ${CMAKE_COMMAND}
        --install "${BUILD_SIMULATOR}" --config ${BUILD_TYPE} --prefix "${INSTALL_SIMULATOR}"
    RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Failed to install simulator build.")
endif()

# --- Verify expected install artifacts ---
#
# Fail loudly with a clear message if something upstream (a renamed target,
# a changed install prefix layout, a disabled MPSS_BUILD_MPSS_OPENSSL build)
# broke our assumptions, rather than letting xcodebuild emit a confusing
# "file not found" error later.

if(BUILD_TYPE STREQUAL "Debug")
    set(CORE_LIB "libmpss_static_debug.a")
    set(OPENSSL_LIB "libmpss_openssl_static_debug.a")
else()
    set(CORE_LIB "libmpss_static.a")
    set(OPENSSL_LIB "libmpss_openssl_static.a")
endif()

set(_expected_libs "${CORE_LIB}")
if(BUILD_MPSS_OPENSSL)
    list(APPEND _expected_libs "${OPENSSL_LIB}")
endif()

foreach(_slice IN ITEMS "${INSTALL_DEVICE}" "${INSTALL_SIMULATOR}")
    foreach(_libname IN LISTS _expected_libs)
        if(NOT EXISTS "${_slice}/lib/${_libname}")
            message(FATAL_ERROR
                "Expected install artifact not found: ${_slice}/lib/${_libname}")
        endif()
    endforeach()
    if(NOT IS_DIRECTORY "${_slice}/include/mpss")
        message(FATAL_ERROR
            "Expected include directory not found: ${_slice}/include/mpss")
    endif()
    if(BUILD_MPSS_OPENSSL AND NOT IS_DIRECTORY "${_slice}/include/mpss-openssl")
        message(FATAL_ERROR
            "Expected include directory not found: ${_slice}/include/mpss-openssl")
    endif()
endforeach()

# --- Create XCFrameworks ---

# Stage headers per platform slice. XCFramework needs separate header trees
# because config.h may differ between device and simulator.
file(REMOVE_RECURSE "${XCF_STAGING}")
file(COPY "${INSTALL_DEVICE}/include/mpss"
     DESTINATION "${XCF_STAGING}/mpss/device")
file(COPY "${INSTALL_SIMULATOR}/include/mpss"
     DESTINATION "${XCF_STAGING}/mpss/simulator")

# xcodebuild refuses to overwrite an existing .xcframework output, so clear
# any prior bundles before re-creating them.
set(CORE_XCF "${OUTPUT_DIR}/libmpss.xcframework")
file(REMOVE_RECURSE "${CORE_XCF}")

message(STATUS "Creating core XCFramework...")
execute_process(
    COMMAND xcodebuild -create-xcframework
        -library "${INSTALL_DEVICE}/lib/${CORE_LIB}"
        -headers "${XCF_STAGING}/mpss/device"
        -library "${INSTALL_SIMULATOR}/lib/${CORE_LIB}"
        -headers "${XCF_STAGING}/mpss/simulator"
        -output "${CORE_XCF}"
    RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Failed to create core XCFramework.")
endif()
message(STATUS "Created: ${CORE_XCF}")

if(BUILD_MPSS_OPENSSL)
    # Stage mpss-openssl headers.
    file(COPY "${INSTALL_DEVICE}/include/mpss-openssl"
         DESTINATION "${XCF_STAGING}/mpss-openssl/device")
    file(COPY "${INSTALL_SIMULATOR}/include/mpss-openssl"
         DESTINATION "${XCF_STAGING}/mpss-openssl/simulator")

    # Include OpenSSL headers from vcpkg if available. Both slices must
    # have them; otherwise the XCFramework headers tree would be asymmetric
    # and the file(COPY) of the missing slice would fail with an unhelpful
    # error.
    set(_dev_openssl_inc "${BUILD_DEVICE}/vcpkg_installed/arm64-ios/include/openssl")
    set(_sim_openssl_inc "${BUILD_SIMULATOR}/vcpkg_installed/arm64-ios/include/openssl")
    if(EXISTS "${_dev_openssl_inc}" AND EXISTS "${_sim_openssl_inc}")
        file(COPY "${_dev_openssl_inc}"
             DESTINATION "${XCF_STAGING}/mpss-openssl/device")
        file(COPY "${_sim_openssl_inc}"
             DESTINATION "${XCF_STAGING}/mpss-openssl/simulator")
    endif()

    set(OPENSSL_XCF "${OUTPUT_DIR}/libmpss-openssl.xcframework")
    # See note above: xcodebuild won't overwrite an existing .xcframework.
    file(REMOVE_RECURSE "${OPENSSL_XCF}")

    message(STATUS "Creating OpenSSL provider XCFramework...")
    execute_process(
        COMMAND xcodebuild -create-xcframework
            -library "${INSTALL_DEVICE}/lib/${OPENSSL_LIB}"
            -headers "${XCF_STAGING}/mpss-openssl/device"
            -library "${INSTALL_SIMULATOR}/lib/${OPENSSL_LIB}"
            -headers "${XCF_STAGING}/mpss-openssl/simulator"
            -output "${OPENSSL_XCF}"
        RESULT_VARIABLE result
    )
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "Failed to create OpenSSL provider XCFramework.")
    endif()
    message(STATUS "Created: ${OPENSSL_XCF}")
endif()

# Cleanup staging directory.
file(REMOVE_RECURSE "${XCF_STAGING}")

message(STATUS "Done. XCFramework(s) are in: ${OUTPUT_DIR}")
