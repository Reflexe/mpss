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

cmake_minimum_required(VERSION 3.25)

# Defaults.
if(NOT DEFINED BUILD_TYPE)
    set(BUILD_TYPE Release)
endif()
if(NOT DEFINED BUILD_MPSS_OPENSSL)
    set(BUILD_MPSS_OPENSSL ON)
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
    -DMPSS_BUILD_MPSS_CORE_STATIC=ON
    -DMPSS_BUILD_MPSS_OPENSSL_STATIC=${BUILD_MPSS_OPENSSL}
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

# --- Create XCFrameworks ---

# Stage headers per platform slice. XCFramework needs separate header trees
# because config.h may differ between device and simulator.
file(REMOVE_RECURSE "${XCF_STAGING}")
file(COPY "${INSTALL_DEVICE}/include/mpss"
     DESTINATION "${XCF_STAGING}/mpss/device")
file(COPY "${INSTALL_SIMULATOR}/include/mpss"
     DESTINATION "${XCF_STAGING}/mpss/simulator")

# Determine library filename based on build type.
if(BUILD_TYPE STREQUAL "Debug")
    set(CORE_LIB "libmpss_static_debug.a")
    set(OPENSSL_LIB "libmpss_openssl_static_debug.a")
else()
    set(CORE_LIB "libmpss_static.a")
    set(OPENSSL_LIB "libmpss_openssl_static.a")
endif()

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

    # Include OpenSSL headers from vcpkg if available.
    if(EXISTS "${BUILD_DEVICE}/vcpkg_installed/arm64-ios/include/openssl")
        file(COPY "${BUILD_DEVICE}/vcpkg_installed/arm64-ios/include/openssl"
             DESTINATION "${XCF_STAGING}/mpss-openssl/device")
        file(COPY "${BUILD_SIMULATOR}/vcpkg_installed/arm64-ios/include/openssl"
             DESTINATION "${XCF_STAGING}/mpss-openssl/simulator")
    endif()

    set(OPENSSL_XCF "${OUTPUT_DIR}/libmpss-openssl.xcframework")
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
